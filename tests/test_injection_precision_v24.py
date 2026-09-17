"""The three precision gates the v24 discovery-run audit earned (5 TP / 6 FP on the classics).

Each test pins the exact FP mechanism observed in multihacksv24.jsonl, and each has a recall twin so a gate
cannot silently become a suppression: mesh-3d (all payloads answered byte-identically), cognify (an LLM SSE
stream whose response size varied arbitrarily), and the flaky-edge-cache shape that passed three coin flips
at grade time.
"""
import httpx
import pytest

from sloptic.probes import _tech_boolean

_T = "1' OR '1'='1' -- "
_F = "1' OR '1'='2' -- "
