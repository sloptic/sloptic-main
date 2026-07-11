"""Deployers: get a submission to a reachable HTTP base URL, then tear it down.

The pipeline depends only on this interface, so the same fuzzing logic runs against a local
subprocess (dev/CI) or a sandboxed container (production). This is the ONLY stack-specific
seam in the runner.
"""
from __future__ import annotations

import abc
import os
import socket
import subprocess
import sys
import time

import httpx


class DeployHandle:
    def __init__(self, base_url: str):
        self.base_url = base_url


class Deployer(abc.ABC):
    @abc.abstractmethod
    def deploy(self) -> DeployHandle:
        """Bring the app up and return a handle once it answers HTTP (the health gate)."""

    @abc.abstractmethod
    def teardown(self) -> None:
        ...


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _docker(*args: str, timeout: float | None = None) -> subprocess.CompletedProcess[str]:
    """Run a docker CLI command, capturing output. Never raises on nonzero exit — callers inspect
    returncode so a build/run failure becomes a DNF, not a runner crash."""
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)


class SubprocessDeployer(Deployer):
    """Dev/CI deployer for TRUSTED reference apps only. Launches the app as a local subprocess
    on an injected $PORT and waits for the health gate.

    NEVER use this for untrusted submissions — a bare subprocess has no isolation. Production
    uses DockerDeployer, which runs untrusted code in the sandbox (no egress, quotas, ephemeral).
    """

    def __init__(self, app_script: str, health_timeout: float = 30.0):
        self.app_script = app_script
        self.health_timeout = health_timeout
        self.proc: subprocess.Popen | None = None

    def deploy(self) -> DeployHandle:
        port = _free_port()
        env = {**os.environ, "PORT": str(port)}
        self.proc = subprocess.Popen(
            [sys.executable, self.app_script],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        base = f"http://127.0.0.1:{port}"
        deadline = time.time() + self.health_timeout
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError("reference app exited during startup")
            try:
                r = httpx.get(base + "/", timeout=1.0)
                if r.status_code < 500:
                    return DeployHandle(base)
            except httpx.HTTPError:
                pass
            time.sleep(0.15)
        raise TimeoutError("health gate failed: app did not respond in time (this would be a DNF)")

    def teardown(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()


class DockerDeployer(Deployer):
    """Production deployer: builds the submission's Dockerfile and runs the image in a sandboxed
    container, injecting ONLY ``$PORT`` (self-containment policy, format_spec §5.7). Safe for
    untrusted code; requires Docker on the host.

    Always-on: ephemeral container, fixed CPU/RAM/PID quotas, ``--cap-drop=ALL``,
    ``--security-opt=no-new-privileges``. Hardening toggles default OFF so the reference
    calibration runs on a stock daemon, and are flipped ON for untrusted production:

    * ``read_only=True`` — read-only root filesystem (+ a writable ``/tmp`` tmpfs)
    * ``network="<net>"`` — egress block via a docker network created with ``--internal``; on a
      custom network the runner reaches the container by its address there (host port-publishing
      does not route on an internal network)
    * ``runtime="runsc"`` — gVisor (or a Firecracker microVM) for container-escape defense

    See FUZZ_RUNNER_SPEC "Production deploy (DockerDeployer)". The reference Dockerfiles let the
    calibration suite run through this deployer unchanged and produce identical scores; see
    tests/test_docker_deploy.py.
    """

    def __init__(
        self,
        context_dir: str,
        *,
        image_tag: str | None = None,
        health_timeout: float = 60.0,
        build_timeout: float = 300.0,
        memory: str = "512m",
        cpus: str = "1.0",
        pids_limit: int = 256,
        read_only: bool = False,
        network: str | None = None,
        runtime: str | None = None,
        remove_image: bool = True,
    ):
        self.context_dir = os.path.abspath(context_dir)
        self.image_tag = (image_tag or "hacklet-sub-" + os.path.basename(self.context_dir)).lower()
        self.health_timeout = health_timeout
        self.build_timeout = build_timeout
        self.memory = memory
        self.cpus = cpus
        self.pids_limit = pids_limit
        self.read_only = read_only
        self.network = network
        self.runtime = runtime
        self.remove_image = remove_image
        self.container_id: str | None = None

    def deploy(self) -> DeployHandle:
        self._build()
        port = _free_port()
        self.container_id = self._run_container(port)
        # On a custom (e.g. --internal) network, host port-publishing does not route; reach the
        # container by its address on that network. On the default bridge, use the loopback port.
        host = self._container_ip() if self.network else "127.0.0.1"
        base = f"http://{host}:{port}"
        self._await_health(base)
        return DeployHandle(base)

    def teardown(self) -> None:
        if self.container_id:
            _docker("rm", "-f", self.container_id)
            self.container_id = None
        if self.remove_image:
            _docker("rmi", "-f", self.image_tag)

    # -- internals ------------------------------------------------------------
    def _build(self) -> None:
        proc = _docker(
            "build", "-t", self.image_tag,
            "-f", os.path.join(self.context_dir, "Dockerfile"),
            self.context_dir,
            timeout=self.build_timeout,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"docker build failed (DNF):\n{proc.stderr[-2000:]}")

    def _run_container(self, port: int) -> str:
        args = [
            "run", "-d",
            "-e", f"PORT={port}",
            "--memory", self.memory,
            "--cpus", self.cpus,
            "--pids-limit", str(self.pids_limit),
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--label", "hacklet-runner=1",
        ]
        if self.network:
            args += ["--network", self.network]  # reached by container IP, not a published port
        else:
            args += ["-p", f"127.0.0.1:{port}:{port}"]
        if self.read_only:
            args += ["--read-only", "--tmpfs", "/tmp"]
        if self.runtime:
            args += ["--runtime", self.runtime]
        args.append(self.image_tag)
        proc = _docker(*args)
        if proc.returncode != 0:
            raise RuntimeError(f"docker run failed:\n{proc.stderr[-2000:]}")
        return proc.stdout.strip()

    def _await_health(self, base: str) -> None:
        deadline = time.time() + self.health_timeout
        while time.time() < deadline:
            if not self._container_running():
                raise RuntimeError(f"container exited during startup (DNF):\n{self._logs()}")
            try:
                if httpx.get(base + "/", timeout=1.0).status_code < 500:
                    return
            except httpx.HTTPError:
                pass
            time.sleep(0.2)
        raise TimeoutError("health gate failed: container did not respond in time (DNF)")

    def _container_running(self) -> bool:
        proc = _docker("inspect", "-f", "{{.State.Running}}", self.container_id or "")
        return proc.returncode == 0 and proc.stdout.strip() == "true"

    def _container_ip(self) -> str:
        # The address on THIS network specifically; ranging over all networks would concat IPs.
        fmt = '{{(index .NetworkSettings.Networks "%s").IPAddress}}' % self.network
        proc = _docker("inspect", "-f", fmt, self.container_id or "")
        ip = proc.stdout.strip()
        if not ip:
            raise RuntimeError(f"could not resolve container IP on '{self.network}':\n{proc.stderr}")
        return ip

    def _logs(self) -> str:
        proc = _docker("logs", "--tail", "50", self.container_id or "")
        return (proc.stdout + proc.stderr)[-2000:]


class RemoteDeployer(Deployer):
    """Targets an already-running HTTP endpoint — dogfooding the league's own site, or any URL you
    own or are authorized to test. 'Deploys' nothing, so it needs no Docker and runs on any box
    (including the dev machine). The pipeline (discover -> probe -> aggregate) is identical to a
    submission; only deploy/teardown differ. teardown is a no-op — the target is not ours to stop.
    """

    def __init__(self, base_url: str, health_timeout: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self.health_timeout = health_timeout

    def deploy(self) -> DeployHandle:
        deadline = time.time() + self.health_timeout
        while time.time() < deadline:
            try:
                # health-check the target AS GIVEN (httpx defaults a bare origin to "/"). Do NOT append
                # "/": a target with a path (e.g. .../portal.php, pointing at a specific vuln page) would
                # become ".../portal.php/", which on some apps (bWAPP) triggers a relative-redirect loop
                # -> TooManyRedirects -> a false "did not respond".
                if httpx.get(self.base_url, timeout=3.0, follow_redirects=True,
                             verify=False).status_code < 500:   # target may present a self-signed cert
                    return DeployHandle(self.base_url)  # a non-5xx response means it is up
            except httpx.HTTPError:
                pass
            time.sleep(0.3)
        raise RuntimeError(f"target did not respond (or only 5xx): {self.base_url}")

    def teardown(self) -> None:
        pass  # never tear down a target we did not deploy
