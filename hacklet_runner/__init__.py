"""Sloptic — a black-box HTTP resilience grader.

Deploys a submission to a reachable HTTP base URL, discovers its surface, runs the
applicable catalog probes, and sums per-probe penalties into a slop score. The deploy step
is abstracted behind a Deployer so the same pipeline runs against a local subprocess (dev/CI,
trusted reference apps) or a sandboxed Docker container (production, untrusted submissions).
"""
