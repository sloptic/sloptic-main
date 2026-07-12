"""The corruption guarantee: N graders appending to one --results file concurrently must never interleave
or drop a record. Large records (findings + evidence) exceed the OS single-write atomic size, so this
would fail with a bare open('a')+write; the flock in append_jsonl serializes them."""
import concurrent.futures
import json

from hacklet_runner.jsonl import append_jsonl


def test_concurrent_appends_never_corrupt(tmp_path):
    path = str(tmp_path / "results.jsonl")
    # 20KB records (well past the ~4KB atomic-write threshold) hammered from 16 threads at once
    def one(i):
        append_jsonl(path, {"i": i, "blob": "x" * 20000, "findings": list(range(60))})

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
        list(ex.map(one, range(300)))

    lines = [ln for ln in open(path).read().splitlines() if ln.strip()]
    assert len(lines) == 300                                   # nothing lost or spliced into a neighbor
    parsed = [json.loads(ln) for ln in lines]                  # every line is intact JSON (would raise if interleaved)
    assert sorted(r["i"] for r in parsed) == list(range(300))  # every record present exactly once
    assert all(len(r["blob"]) == 20000 for r in parsed)        # no record truncated mid-write
