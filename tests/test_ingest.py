"""Submission-ingestion tests — pure filesystem, no Docker, so they run on the dev box.

Cover the happy paths (Dockerfile at root / in a single top-level folder) and the untrusted-input
guards (no Dockerfile, zip-slip, not-a-zip), since submissions are hostile by assumption.
"""
import zipfile

import pytest

from hacklet_runner.ingest import SubmissionError, extract_submission


def _make_zip(path, files: dict):
    with zipfile.ZipFile(path, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)


def test_extracts_root_dockerfile(tmp_path):
    z = tmp_path / "sub.zip"
    _make_zip(z, {"Dockerfile": "FROM scratch\n", "app.py": "x = 1\n"})
    sub = extract_submission(z)
    try:
        assert (sub.context_dir / "Dockerfile").is_file()
        assert (sub.context_dir / "app.py").is_file()
    finally:
        sub.cleanup()


def test_finds_dockerfile_in_single_top_folder(tmp_path):
    z = tmp_path / "sub.zip"
    _make_zip(z, {"myapp/Dockerfile": "FROM scratch\n", "myapp/app.py": "x = 1\n"})
    sub = extract_submission(z)
    try:
        assert sub.context_dir.name == "myapp"
        assert (sub.context_dir / "Dockerfile").is_file()
    finally:
        sub.cleanup()


def test_missing_dockerfile_is_error(tmp_path):
    z = tmp_path / "sub.zip"
    _make_zip(z, {"app.py": "x = 1\n"})
    with pytest.raises(SubmissionError):
        extract_submission(z)


def test_zip_slip_is_rejected(tmp_path):
    z = tmp_path / "evil.zip"
    _make_zip(z, {"../escape.txt": "pwned\n", "Dockerfile": "FROM scratch\n"})
    with pytest.raises(SubmissionError):
        extract_submission(z)


def test_rejects_zip_bomb(tmp_path, monkeypatch):
    import hacklet_runner.ingest as ingest
    monkeypatch.setattr(ingest, "MAX_TOTAL_BYTES", 1000)  # tiny cap for the test
    z = tmp_path / "bomb.zip"
    with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("Dockerfile", "FROM scratch\n")
        zf.writestr("big.txt", "A" * 100_000)  # ~100 KB decompressed, far over the patched cap
    with pytest.raises(SubmissionError):
        extract_submission(z)


def test_not_a_zip_is_error(tmp_path):
    bad = tmp_path / "notazip.zip"
    bad.write_text("i am not a zip")
    with pytest.raises(SubmissionError):
        extract_submission(bad)


def test_missing_file_is_error(tmp_path):
    with pytest.raises(SubmissionError):
        extract_submission(tmp_path / "does-not-exist.zip")
