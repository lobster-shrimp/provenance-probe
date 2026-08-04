"""Auto-detect what kind of endpoint the operator pasted, so the wizard never
asks "which API style?" (CEO plan E2 + spec review).

Two layers:

1. `classify_input()` — LOCAL, no network. Decides whether a pasted string is a
   `curl` command, a HAR export, a plain endpoint/URL, or something unusable.

2. `detect()` — the API-probe state machine for the endpoint path. It probes the
   endpoint (passive first, then active) and infers `api_style` (openai |
   anthropic) by OBSERVING responses, never by guessing from the URL alone.

Hard invariants (spec review — a CRITICAL probe-before-consent flaw was caught):

* CONSENT GATE — `detect()` sends NOTHING over the network unless `consented`
  is True. The first egress is gated on the caller having shown the consent copy
  and the operator having approved. This is enforced here, not just in the UI.
* EGRESS BUDGET (outside-voice #3) — `EgressBudget` caps `detect()`'s probe
  fan-out and can be shared into the same session's dry-run. It bounds the
  identify phase so it can't runaway. NOTE: the fingerprint battery runs in a
  separate flow with its own fixed bound; a single budget spanning detect +
  battery is a P2 refinement, not wired here — so this caps detect (+ an
  optionally-shared dry-run), not literally every request in the whole session.
* LLM-POSITIVE requires the FULL combination — assistant-content string AND
  usage integer AND a model id — else the result is INDETERMINATE. A bare JSON
  200 is not enough (false-positive JSON detection was a spec-review finding).
* Every verdict carries a self-reported-usage CAVEAT (outside-voice #6):
  `usage.prompt_tokens` is reported by the endpoint and could be forged to spoof
  a tokenizer shape; it is a signal, not proof.
* Friendly errors only (E6) — connection/timeout/DNS/TLS/HTTP are mapped to
  plain sentences; no stack traces reach the operator.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

# A pasted string is an endpoint if it's a lone URL or bare host (no spaces).
_URL_RE = re.compile(r"^https?://", re.IGNORECASE)
_BARE_HOST_RE = re.compile(r"^[\w-]+(\.[\w-]+)+(/\S*)?$")  # api.vendor.com[/path]


# --------------------------------------------------------------------------- #
# Session egress budget (outside-voice #3)
# --------------------------------------------------------------------------- #

class EgressBudgetExceeded(RuntimeError):
    """Raised when a probe would exceed the session-wide outbound cap."""


class EgressBudget:
    """A cap on outbound requests for the identify phase (and a shared dry-run).

    Bounds `detect()`'s probe fan-out so it's visible and un-runaway, rather than
    an implicit "one test" that is really several calls. Pass the SAME instance
    into a follow-on dry-run to bound them together; the fingerprint battery is
    bounded separately (see the module docstring).
    """

    def __init__(self, max_requests: int = 40):
        self.max_requests = max_requests
        self.used = 0

    def spend(self, n: int = 1) -> None:
        if self.used + n > self.max_requests:
            raise EgressBudgetExceeded(
                f"egress budget exhausted ({self.used}/{self.max_requests} requests used); "
                f"stopping to avoid unbounded calls to the target.")
        self.used += n

    def remaining(self) -> int:
        return max(0, self.max_requests - self.used)


# --------------------------------------------------------------------------- #
# Input classification (LOCAL, no network)
# --------------------------------------------------------------------------- #

def classify_input(text: str) -> str:
    """Classify a pasted capture with NO network access.

    Returns one of: 'empty' | 'curl' | 'har' | 'endpoint' | 'unknown'.
    The caller routes curl/har to the existing wizard parsers and 'endpoint' to
    detect(); 'unknown' gets a friendly "I couldn't tell what this is" message.
    """
    t = (text or "").strip()
    if not t:
        return "empty"
    low = t.lower()
    if low == "curl" or low.startswith("curl ") or low.startswith("curl\t") or low.startswith("curl\n"):
        return "curl"
    if t.startswith("{") or t.startswith("["):
        # JSON paste — treat as HAR (parse_har validates and errors friendly if
        # it isn't a HAR). Endpoints are never JSON, so this is unambiguous here.
        return "har"
    single = t.split()
    if len(single) == 1 and (_URL_RE.match(t) or _BARE_HOST_RE.match(t)):
        return "endpoint"
    return "unknown"


# --------------------------------------------------------------------------- #
# Probe transport (injectable for tests)
# --------------------------------------------------------------------------- #

@dataclass
class ProbeResult:
    status: int
    json: object = None
    headers: dict = field(default_factory=dict)
    error: str = ""       # friendly network error (empty on an HTTP response)
    text: str = ""        # raw body (for HTML/login-wall detection)

    @property
    def ok(self) -> bool:
        return not self.error and 200 <= self.status < 300


def _friendly_net_error(exc: Exception) -> str:
    """Map a transport exception to a plain sentence (E6 — no stack traces)."""
    name = type(exc).__name__.lower()
    s = str(exc).lower()
    if "timeout" in name or "timed out" in s:
        return "the endpoint didn't respond in time (timeout) — it may be slow or unreachable."
    if "ssl" in name or "certificate" in s or "tls" in s:
        return "the endpoint's TLS certificate could not be verified — check the URL / try http for a local endpoint."
    if "connection" in name or "refused" in s or "name or service" in s or "resolve" in s or "nodename" in s:
        return "couldn't connect — check the address is right and the service is reachable from this machine."
    return "the network request failed — check the address and your connection."


def _default_probe(method: str, url: str, headers: dict, body: dict | None,
                   timeout: float = 8.0) -> ProbeResult:
    import requests
    # Public-hosting mode: /wizard/detect reaches this with a user-supplied URL,
    # so route through the SSRF egress guard when the flag is set (a private/
    # metadata endpoint is refused before any socket opens). When the flag is
    # unset the transport is byte-identical to before.
    from . import egress
    getter = requests
    session = None
    if egress.guard_enabled():
        session = requests.Session()
        egress.install_guard(session)
        getter = session
    try:
        if method == "GET":
            r = getter.get(url, headers=headers, timeout=timeout)
        else:
            r = getter.post(url, headers=headers, json=body, timeout=timeout)
        try:
            j = r.json()
        except Exception:
            j = None
        return ProbeResult(r.status_code, j,
                           {k.lower(): v for k, v in r.headers.items()},
                           text=r.text[:4096] if j is None else "")
    except Exception as e:   # requests.RequestException + anything transport-y
        return ProbeResult(0, None, {}, error=_friendly_net_error(e))
    finally:
        if session is not None:
            session.close()


# --------------------------------------------------------------------------- #
# Detection result
# --------------------------------------------------------------------------- #

@dataclass
class Detection:
    ok: bool = False
    api_style: str = ""            # openai | anthropic | "" (unknown)
    base_url: str = ""
    chat_path: str = ""
    model: str = ""                # a model id we can probe with, if discovered
    confidence: str = "none"       # high | medium | low | none
    needs_confirm: bool = False    # E6 — ambiguous/partial -> ALWAYS confirm
    passive_only: bool = False
    llm_positive: bool = False
    probes_used: int = 0
    candidates: list = field(default_factory=list)   # [(api_style, score)]
    models: list = field(default_factory=list)       # catalog ids (passive)
    error: str = ""                # friendly, human (no stack trace)
    caveat: str = ""               # self-reported-usage caveat (finding #6)
    route_hint: str = ""           # "capture" -> looks like a web app (E8), etc.
    evidence: dict = field(default_factory=dict)     # raw signals for details view


_USAGE_CAVEAT = ("prompt-token usage is self-reported by the endpoint; a hostile "
                 "endpoint could forge it to spoof a tokenizer shape. The fingerprint "
                 "treats it as a signal, not proof.")


# --------------------------------------------------------------------------- #
# Endpoint normalization
# --------------------------------------------------------------------------- #

def _normalize(text: str) -> tuple[str, str]:
    """Return (base_url, full_endpoint_url_or_empty).

    Accepts 'api.x.com', 'https://api.x.com/v1', or a full
    '.../v1/chat/completions'. If a full chat endpoint was pasted, `full` is the
    EXACT absolute URL to POST (probed as-given); `base` is that URL with the
    chat suffix stripped, used for GET /models. `full` is a complete URL, never
    concatenated onto `base` (which would double the path).
    """
    from urllib.parse import urlsplit
    t = text.strip()
    if not _URL_RE.match(t):
        t = "https://" + t
    parts = urlsplit(t)
    path = parts.path.rstrip("/")
    base_path, full = path, ""
    for suffix in ("/chat/completions", "/v1/messages", "/messages", "/completions"):
        if path.endswith(suffix):
            full = f"{parts.scheme}://{parts.netloc}{path}"   # exact pasted endpoint
            base_path = path[: -len(suffix)]
            break
    base = f"{parts.scheme}://{parts.netloc}{base_path}".rstrip("/")
    return base, full


def _auth_headers(key: str | None, scheme: str) -> dict:
    """Build headers for one auth scheme. scheme = 'bearer' | 'x-api-key'."""
    h = {"Content-Type": "application/json", "Accept": "application/json"}
    if key:
        if scheme == "bearer":
            h["Authorization"] = f"Bearer {key}"
        else:
            h["x-api-key"] = key
            h["anthropic-version"] = "2023-06-01"
    return h


# --------------------------------------------------------------------------- #
# LLM-positive shape checks (the full combination or INDETERMINATE)
# --------------------------------------------------------------------------- #

def _openai_fields(j) -> dict:
    if not isinstance(j, dict):
        return {"content": False, "usage": False, "model": False}
    content = None
    try:
        content = j["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        content = None
    usage = (j.get("usage") or {}).get("prompt_tokens") if isinstance(j.get("usage"), dict) else None
    model = j.get("model")
    return {"content": isinstance(content, str),
            "usage": isinstance(usage, int),
            "model": isinstance(model, str) and bool(model)}


def _anthropic_fields(j) -> dict:
    if not isinstance(j, dict):
        return {"content": False, "usage": False, "model": False}
    content = None
    c = j.get("content")
    if isinstance(c, list) and c and isinstance(c[0], dict):
        content = c[0].get("text")
    usage = (j.get("usage") or {}).get("input_tokens") if isinstance(j.get("usage"), dict) else None
    model = j.get("model")
    return {"content": isinstance(content, str),
            "usage": isinstance(usage, int),
            "model": isinstance(model, str) and bool(model)}


def _looks_like_html(pr: ProbeResult) -> bool:
    if pr.json is not None:
        return False
    body = (pr.text or "").lstrip().lower()
    ct = (pr.headers.get("content-type") or "").lower()
    return "text/html" in ct or body.startswith("<!doctype") or body.startswith("<html")


def _catalog_models(j) -> list:
    """Extract model ids from an OpenAI-style GET /models response."""
    if isinstance(j, dict) and isinstance(j.get("data"), list):
        ids = [m.get("id") for m in j["data"] if isinstance(m, dict) and isinstance(m.get("id"), str)]
        return [i for i in ids if i]
    if isinstance(j, list):
        return [m.get("id") for m in j if isinstance(m, dict) and isinstance(m.get("id"), str)]
    return []


# --------------------------------------------------------------------------- #
# The state machine
# --------------------------------------------------------------------------- #

def detect(text: str, key: str | None = None, *, consented: bool = False,
           passive_only: bool = False, budget: EgressBudget | None = None,
           probe=None, max_probes: int = 6) -> Detection:
    """Identify an endpoint by observing it. See module docstring for invariants.

    `key` is the token VALUE, resolved in-memory by the caller (never persisted).
    `probe` is an injectable transport (method,url,headers,body)->ProbeResult;
    defaults to a real `requests` call. `budget` is the session egress budget.
    """
    d = Detection(passive_only=passive_only, caveat=_USAGE_CAVEAT)
    kind = classify_input(text)
    if kind != "endpoint":
        d.error = (f"this doesn't look like a plain endpoint (looks like: {kind}). "
                   f"Paste a URL like https://api.vendor.com/v1, or a curl/HAR capture.")
        d.needs_confirm = True
        return d

    # CONSENT GATE — no network egress without explicit approval.
    if not consented:
        d.needs_confirm = True
        d.error = ("Consent required — nothing was sent. I'll send a few short requests to "
                   "identify this service only after you approve, and only test services "
                   "you're authorized to. A full check is ~28 requests total.")
        return d

    budget = budget or EgressBudget()
    probe = probe or _default_probe
    base, full = _normalize(text)
    d.base_url = base

    def _spend_probe(method, url, headers, body):
        if d.probes_used >= max_probes:
            raise EgressBudgetExceeded(f"local probe cap reached ({max_probes})")
        budget.spend(1)
        d.probes_used += 1
        return probe(method, url, headers, body)

    try:
        # --- PASSIVE: GET /models (reachability + a model id to probe with) ----
        # A base that already ends in /v1 has its catalog at base/models; a bare
        # host (no /v1) may need base/v1/models. Never append /v1 to a /v1 base
        # (that doubles the path).
        has_v1 = base.endswith(("/v1", "/v1beta/openai"))
        primary = base + "/models"
        models_pr = _spend_probe("GET", primary, _auth_headers(key, "bearer"), None)
        if models_pr.status == 401 and key:
            # Same path, anthropic-style auth (x-api-key) rather than Bearer.
            models_pr = _spend_probe("GET", primary, _auth_headers(key, "x-api-key"), None)
        elif not models_pr.ok and models_pr.status != 429 and not has_v1:
            alt = _spend_probe("GET", base + "/v1/models", _auth_headers(key, "bearer"), None)
            if alt.ok:
                models_pr = alt
        if models_pr.error:
            d.error = models_pr.error
            d.needs_confirm = True
            return d
        if _looks_like_html(models_pr):
            d.route_hint = "capture"
            d.error = ("this looks like a web app (HTML), not an API — use the paste flow: "
                       "sign in, send one message, and copy the request as cURL or HAR.")
            d.needs_confirm = True
            return d
        d.models = _catalog_models(models_pr.json)
        if d.models:
            d.model = d.models[0]
        d.evidence["models_status"] = models_pr.status

        if passive_only:
            # No inference sent. We have reachability + maybe a catalog, but not a
            # confirmed shape — always confirm the api_style with the operator.
            d.ok = bool(d.models)
            d.confidence = "low"
            d.needs_confirm = True
            d.error = "" if d.models else ("reachable, but no model catalog was returned; "
                                           "send an active test or confirm the API style.")
            return d

        # --- ACTIVE: try the two shapes deterministically (max_tokens=1) -------
        # `full` (if present) is a complete URL — probe it as-given, never
        # concatenated onto base (that would double the path).
        model = d.model or "gpt-3.5-turbo"
        oa_url = full if full.endswith(("/chat/completions", "/completions")) else base + "/chat/completions"
        oa_body = {"model": model, "messages": [{"role": "user", "content": "ping"}],
                   "max_tokens": 1, "temperature": 0}
        oa_pr = _spend_probe("POST", oa_url, _auth_headers(key, "bearer"), oa_body)

        if full.endswith(("/v1/messages", "/messages")):
            an_url = full
        elif base.endswith("/v1"):
            an_url = base + "/messages"          # base already carries /v1 (no doubling)
        else:
            an_url = base + "/v1/messages"
        an_model = d.model or "claude-3-haiku-20240307"
        an_body = {"model": an_model, "max_tokens": 1,
                   "messages": [{"role": "user", "content": "ping"}]}
        an_pr = _spend_probe("POST", an_url, _auth_headers(key, "x-api-key"), an_body)

        oa_fields = _openai_fields(oa_pr.json)
        an_fields = _anthropic_fields(an_pr.json)
        oa_score, an_score = sum(oa_fields.values()), sum(an_fields.values())
        oa_pos, an_pos = all(oa_fields.values()), all(an_fields.values())
        d.candidates = [("openai", oa_score), ("anthropic", an_score)]
        d.evidence.update({"openai": {"status": oa_pr.status, "fields": oa_fields},
                           "anthropic": {"status": an_pr.status, "fields": an_fields}})

        def _echoed(j, fallback):
            m = j.get("model") if isinstance(j, dict) else None
            return m if isinstance(m, str) and m else (d.model or fallback)

        if oa_pos and an_pos:
            # Both full shapes answered — genuinely ambiguous. Never silently pick.
            d.ok, d.llm_positive, d.api_style = True, True, "openai"
            d.chat_path, d.confidence, d.needs_confirm = "/chat/completions", "medium", True
            d.model = _echoed(oa_pr.json, model)
            return d
        if oa_pos:
            d.ok, d.llm_positive, d.api_style = True, True, "openai"
            d.chat_path, d.confidence = "/chat/completions", "high"
            d.model = _echoed(oa_pr.json, model)
            return d
        if an_pos:
            d.ok, d.llm_positive, d.api_style = True, True, "anthropic"
            d.chat_path, d.confidence = "/v1/messages", "high"
            # Set a usable model even without a catalog (else save writes model="").
            d.model = _echoed(an_pr.json, an_model)
            return d

        # Handle rate limiting explicitly before declaring INDETERMINATE.
        if 429 in (oa_pr.status, an_pr.status):
            d.needs_confirm = True
            d.error = ("the endpoint rate-limited the identify test (HTTP 429) — wait a bit "
                       "and retry, or confirm the API style manually.")
            return d

        # A transport failure on BOTH active probes (models GET answered, but the
        # chat POST timed out / TLS-failed) — surface the real error, not "not
        # recognizable" (Codex adversarial). One-sided failure falls through to
        # the shape logic below (the other probe may have answered).
        if oa_pr.error and an_pr.error:
            d.needs_confirm = True
            d.error = oa_pr.error
            return d

        if max(oa_score, an_score) >= 2:
            # Partial shape — a likely guess, but confirm (E6). Never mark positive.
            d.api_style = "openai" if oa_score >= an_score else "anthropic"
            d.chat_path = "/chat/completions" if d.api_style == "openai" else "/v1/messages"
            d.confidence, d.needs_confirm = "low", True
            d.error = (f"partial match to the {d.api_style} shape (missing required fields) — "
                       f"confirm this is right, or the endpoint may need a valid model/key.")
            return d

        # Nothing matched an LLM shape.
        d.needs_confirm = True
        auth_bad = 401 in (oa_pr.status, an_pr.status, d.evidence.get("models_status", 0))
        if auth_bad and not key:
            d.error = ("the endpoint needs an API key (HTTP 401) and none was found in your "
                       "environment — add the key, or use a known-vendor preset.")
        elif auth_bad:
            d.error = ("the endpoint rejected the key (HTTP 401) — check the key is valid for "
                       "this service.")
        else:
            d.error = ("responded, but not with a recognizable chat-completion shape — it may "
                       "not be an LLM API, or it uses a custom protocol. Use the paste flow.")
        return d
    except EgressBudgetExceeded as e:
        d.needs_confirm = True
        d.error = f"stopped early: {e}"
        return d
