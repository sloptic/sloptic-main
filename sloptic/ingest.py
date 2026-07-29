"""Submission ingestion: safely unpack a contestant zip into a build context for the DockerDeployer.

Submissions are untrusted, so extraction guards against zip-slip (path traversal via `../` or
absolute members) and zip bombs (file-count / uncompressed-size caps). The Dockerfile is located at
the archive root or one level down (the common single-top-level-folder layout), and that directory
is returned as the build context.
"""
from __future__ import annotations

import pathlib
import shutil
import tempfile
import zipfile
from dataclasses import dataclass

MAX_FILES = 10_000
MAX_TOTAL_BYTES = 500 * 1024 * 1024  # 500 MB uncompressed (zip-bomb guard)
_CHUNK = 1 << 16  # 64 KiB streaming-extract chunk


class SubmissionError(Exception):
    """The archive is malformed, unsafe, or has no Dockerfile — a DNF, not a runner crash."""


@dataclass
class Submission:
    context_dir: pathlib.Path   # directory containing the Dockerfile (the build context)
    extract_root: pathlib.Path  # temp root to remove when done

    def cleanup(self) -> None:
        shutil.rmtree(self.extract_root, ignore_errors=True)


def _safe_extract(zf: zipfile.ZipFile, dest: pathlib.Path) -> None:
    dest = dest.resolve()
    infos = zf.infolist()
    if len(infos) > MAX_FILES:
        raise SubmissionError(f"too many entries ({len(infos)} > {MAX_FILES})")
    written = 0
    for info in infos:
        # zip-slip guard: every member must resolve to a path under dest (absolute or `..` escapes).
        target = (dest / info.filename).resolve()
        if target != dest and dest not in target.parents:
            raise SubmissionError(f"unsafe path in archive: {info.filename!r}")
        if info.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        # Stream-extract, capping ACTUAL decompressed bytes. Never trust info.file_size — a zip
        # bomb forges it small; counting real bytes aborts before GBs hit disk.
        with zf.open(info) as src, open(target, "wb") as out:
            while chunk := src.read(_CHUNK):
                written += len(chunk)
                if written > MAX_TOTAL_BYTES:
                    raise SubmissionError("archive too large uncompressed (zip-bomb guard)")
                out.write(chunk)


def _find_context(root: pathlib.Path) -> pathlib.Path:
    if (root / "Dockerfile").is_file():
        return root
    # common case: a single top-level project folder (ignore macOS zip cruft)
    entries = [p for p in root.iterdir() if p.name != "__MACOSX"]
    if len(entries) == 1 and entries[0].is_dir() and (entries[0] / "Dockerfile").is_file():
        return entries[0]
    raise SubmissionError("no Dockerfile at the archive root or in a single top-level folder")


def extract_submission(zip_path: str | pathlib.Path) -> Submission:
    """Unpack a submission zip to a temp build context. Raises SubmissionError on any problem."""
    zip_path = pathlib.Path(zip_path)
    if not zip_path.is_file():
        raise SubmissionError(f"no such file: {zip_path}")
    extract_root = pathlib.Path(tempfile.mkdtemp(prefix="hacklet-sub-"))
    try:
        with zipfile.ZipFile(zip_path) as zf:
            _safe_extract(zf, extract_root)
        return Submission(context_dir=_find_context(extract_root), extract_root=extract_root)
    except zipfile.BadZipFile as e:
        shutil.rmtree(extract_root, ignore_errors=True)
        raise SubmissionError(f"not a valid zip: {e}") from e
    except Exception:
        shutil.rmtree(extract_root, ignore_errors=True)
        raise
