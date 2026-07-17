"""Probe schema + runtime structures. Probe mirrors FUZZ_RUNNER_SPEC's YAML schema (trimmed
to what the vertical slice exercises)."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields
from typing import Any

from pydantic import BaseModel, Field


class Applicability(BaseModel):
    requires: list[str] = Field(default_factory=list)


class Probe(BaseModel):
    id: str
    bundle: str  # security | qa | performance
    category: str = ""
    variant_group_id: str | None = None  # probes sharing one fire once (same logical flaw)
    pool: str = "public"  # public | hidden
    evidence_model: str = "provable"  # provable | oracle (detection hint only)
    penalty: int  # slop added when the probe fires; deduction-only, so always positive
    applicability: Applicability = Field(default_factory=Applicability)
    # Either {"predicate": name} for oracle probes, or {"method", "target"} for declarative ones.
    probe: dict[str, Any] = Field(default_factory=dict)
    # Declarative conditions; ALL must match for slop. Each is a matcher name or {name: arg}.
    slop_if: list[Any] = Field(default_factory=list)


@dataclass
class Form:
    """A discovered HTML form: where it submits, how, and its input field names."""
    action: str
    method: str = "get"
    fields: list[str] = field(default_factory=list)
    enctype: str = ""                                     # e.g. multipart/form-data (file uploads)
    file_fields: list[str] = field(default_factory=list)  # names of <input type=file> controls
    origin: str = "crawl"                                  # "crawl" | "llm" (perceived) — pointer telemetry, never scored
    constraints: dict = field(default_factory=dict)        # field name -> declared constraint {type,required,min,max}
    #     (HTML5 type=email/number/url/date, required, min/max) — the app's OWN contract, tested by qa-input-001


@dataclass
class Endpoint:
    """An API operation discovered from a served OpenAPI/Swagger spec — the JSON-API analogue of a
    Form. Feeds the declarative fan-out (headers/crash/exposure across real endpoints) and the
    injection probes (concrete query params / JSON body fields to inject into)."""
    path: str                                              # concretized path ({id}->1) for fetches
    method: str = "get"                                    # get/post/put/patch/delete
    query_params: list[str] = field(default_factory=list)  # query parameter names
    body_fields: list[str] = field(default_factory=list)   # JSON/form request-body property names
    path_params: list[str] = field(default_factory=list)   # path-template param names (BOLA/IDOR)
    raw_path: str = ""                                      # original template, e.g. /users/v1/{username}
    baseline_status: int | None = None                     # status of a well-formed baseline request;
    #                                    >=500 => env-var-dead (dummy key), so it's reached-but-not-healthy
    kind: str = ""                                          # feature kind if seeded (auth/upload/search/...)
    origin: str = "crawl"                                   # "crawl" (openapi/js-mine/link) | "llm" (source-read
    #                                    feature seed) — off-score pointer-precision telemetry, never scored


@dataclass
class Profile:
    """The stack-agnostic surface map produced by discovery."""
    base_url: str
    routes: list[str] = field(default_factory=list)        # discovered paths (incl "/")
    forms: list[Form] = field(default_factory=list)         # discovered forms with their fields
    capabilities: dict[str, bool] = field(default_factory=dict)
    endpoints: list[Endpoint] = field(default_factory=list)  # API operations from an OpenAPI spec

    @property
    def form_endpoints(self) -> list[str]:  # back-compat for predicates that target form actions
        return [f.action for f in self.forms]


_FORM_FIELDS = {f.name for f in fields(Form)}
_ENDPOINT_FIELDS = {f.name for f in fields(Endpoint)}


def profile_to_dict(profile: Profile) -> dict:
    """Serialize a discovered Profile to a JSON-safe dict for the per-commit SURFACE cache (build 1b).
    Freezes the whole discovered surface — routes/forms/endpoints (incl. each endpoint's frozen
    baseline_status) + capabilities — so a re-grade of the same commit reuses it verbatim instead of
    re-crawling. That removes the browser crawl + interaction clicking's OWN timing non-determinism from
    the score (temp-0 + the plan cache only froze the LLM). base_url is stored for reference but re-bound
    to the fresh deployment on reuse: the surface paths are all relative (base_url is the sole absolute)."""
    return {
        "base_url": profile.base_url,
        "routes": list(profile.routes),
        "forms": [asdict(f) for f in profile.forms],
        "capabilities": dict(profile.capabilities),
        "endpoints": [asdict(e) for e in profile.endpoints],
    }


def profile_from_dict(d: dict) -> Profile:
    """Reconstruct a Profile from profile_to_dict output. Field-tolerant (unknown keys dropped, missing
    ones defaulted) so an older cache file still loads after a benign schema addition — a grader-logic
    change that alters the surface's MEANING is handled out-of-band (bump the cache dir / --no-cache)."""
    forms = [Form(**{k: v for k, v in f.items() if k in _FORM_FIELDS}) for f in d.get("forms") or []]
    endpoints = [Endpoint(**{k: v for k, v in e.items() if k in _ENDPOINT_FIELDS})
                 for e in d.get("endpoints") or []]
    return Profile(base_url=d.get("base_url", ""), routes=list(d.get("routes") or []), forms=forms,
                   capabilities=dict(d.get("capabilities") or {}), endpoints=endpoints)


@dataclass
class Outcome:
    probe_id: str
    bundle: str
    category: str
    outcome: str  # slop_detected | clean | not_applicable
    penalty: int
    variant_group_id: str | None = None
    target: str = ""  # the concrete path/form this outcome ran against (fan-out)
    reason: str = ""  # short human "why it fired" (slop only); derived from the probe's check
    evidence: dict = field(default_factory=dict)  # measured values / what was checked — for ALL
    #                                               outcomes (clean/n/a too), so a report can show
    #                                               "load time 0.4s ✓" / "tried error+union+time, none hit"


@dataclass
class Report:
    slop_score: int                                        # deduction total, unbounded [0, +inf); lower = better
    outcomes: list[Outcome] = field(default_factory=list)
    axis_slop: dict = field(default_factory=dict)          # per-bundle damped subtotal; sums to slop_score
    surface: dict = field(default_factory=dict)            # what discovery SAW (discovery.surface_metrics)
    coverage: dict = field(default_factory=dict)           # how much of the battery APPLIED (coverage_metrics)

    @property
    def by_id(self) -> dict[str, str]:
        # A probe may fan across many targets; collapse to the strongest status seen.
        rank = {"not_applicable": 0, "clean": 1, "slop_detected": 2}
        status: dict[str, str] = {}
        for o in self.outcomes:
            if o.probe_id not in status or rank[o.outcome] > rank[status[o.probe_id]]:
                status[o.probe_id] = o.outcome
        return status
