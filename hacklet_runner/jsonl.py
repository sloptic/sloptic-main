"""Atomic JSONL append. Parallel url grading means N graders append records to ONE --results file at once,
and a record with findings + evidence + coverage_audit easily exceeds the OS single-write atomic size — so
a bare open('a') + write can interleave two records and corrupt a line (a half-written record, or two
spliced together). An advisory exclusive lock (fcntl.flock) around a single flushed write serializes the
appenders; it is held only for the microseconds of the write, so contention is negligible even at high
fan-out. Advisory means EVERY writer must go through here — they do (deploy_and_grade --record and
run_batch's wedge record). Local filesystems only; flock is unreliable over NFS.
"""
import fcntl
import json


def append_jsonl(path, obj) -> None:
    """Append one JSON object as a line, atomically w.r.t. other append_jsonl callers on the same file."""
    line = json.dumps(obj) + "\n"
    with open(path, "a") as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)   # blocks other appenders until we've flushed this whole line
        try:
            f.write(line)
            f.flush()                            # flush WHILE holding the lock — else the buffer flushes on
        finally:                                 # close, AFTER we unlock, re-opening the interleaving window
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
