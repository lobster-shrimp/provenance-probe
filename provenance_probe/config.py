"""Target configuration and scope control."""
from __future__ import annotations
import json, os
from dataclasses import dataclass, field, asdict, fields
from typing import Any


@dataclass
class Target:
    """A single endpoint under assessment."""
    name: str
    base_url: str                       # e.g. https://api.vendor.com/v1
    model: str = ""                     # model id to request (may be a marketing name)
    api_style: str = "openai"           # openai | anthropic | raw | template
    auth_header: str = "Authorization"
    auth_value_env: str = ""            # env var holding the token
    auth_prefix: str = "Bearer "
    extra_headers: dict[str, str] = field(default_factory=dict)
    cookie: str = ""                    # raw Cookie header for web-app sessions
    cookie_env: str = ""                # or an env var holding it (keeps secrets out of config)
    chat_path: str = "/chat/completions"
    models_path: str = "/models"
    # --- Web-app / platform adapter (api_style="template") -------------------
    # Bring a request captured from the web app's browser traffic. The probe
    # prompt is substituted for __PROMPT__ (and optionally __MAX_TOKENS__,
    # __TEMPERATURE__, __SYSTEM__) anywhere in request_template, then POSTed to
    # chat_path. Response fields are read by dotted path (numeric indices ok),
    # e.g. "choices.0.message.content".
    request_template: dict = field(default_factory=dict)
    response_text_path: str = ""            # where the assistant reply text lives
    response_prompt_tokens_path: str = ""   # where prompt-token usage lives (if any)
    response_model_path: str = ""           # where the echoed model id lives (if any)
    stream_mode: str = "none"               # none | sse
    stream_delta_path: str = ""             # per-chunk text delta path for SSE accumulation
    timeout: float = 60.0
    verify_tls: bool = True
    proxy: str = ""                     # route through your inspecting proxy
    # Scope attestation: you must set this to run active probes.
    authorized: bool = False
    notes: str = ""

    def __post_init__(self):
        # Anthropic adapter defaults, so `api_style="anthropic"` alone works: its
        # chat endpoint is /v1/messages and its auth is `x-api-key`, not Bearer.
        if self.api_style == "anthropic":
            if self.chat_path == "/chat/completions":
                self.chat_path = "/v1/messages"
            if self.auth_header == "Authorization":
                self.auth_header, self.auth_prefix = "x-api-key", ""

    def headers(self) -> dict[str, str]:
        h = {"Content-Type": "application/json", "Accept": "application/json"}
        h.update(self.extra_headers)
        if self.auth_value_env:
            tok = os.environ.get(self.auth_value_env, "")
            if tok:
                h[self.auth_header] = f"{self.auth_prefix}{tok}"
        cookie = self.cookie or (os.environ.get(self.cookie_env, "") if self.cookie_env else "")
        if cookie:
            h["Cookie"] = cookie
        if self.api_style == "anthropic":
            h.setdefault("anthropic-version", "2023-06-01")
        return h

    def url(self, path: str) -> str:
        return self.base_url.rstrip("/") + path


@dataclass
class AgentBackend:
    """One model backend an agent calls. Carries its own authorization flag —
    active probing of an agent's backend needs written authorization for THAT
    backend, not just the agent (the consent surface multiplies)."""
    base_url: str
    model: str = ""
    auth_value_env: str = ""
    auth_header: str = "Authorization"
    auth_prefix: str = "Bearer "
    api_style: str = "openai"
    authorized: bool = False

    def to_target(self, name: str) -> "Target":
        return Target(name=name, base_url=self.base_url, model=self.model,
                      api_style=self.api_style, auth_header=self.auth_header,
                      auth_value_env=self.auth_value_env, auth_prefix=self.auth_prefix,
                      authorized=self.authorized)


@dataclass
class AgentTarget:
    """An agent under assessment. The unit is the agent, not one endpoint.

    observation: which surfaces to use — "trace" (general, always works),
    "active-probe" (the only route to CONFIRMED provenance; needs a reachable,
    authorized backend), "proxy" (Phase 2).
    """
    name: str
    observation: list[str] = field(default_factory=lambda: ["trace"])
    trace_path: str = ""
    backends: list[AgentBackend] = field(default_factory=list)
    offline: bool = False
    notes: str = ""

    def __post_init__(self):
        self.backends = [b if isinstance(b, AgentBackend) else _from_dict(AgentBackend, b)
                         for b in self.backends]


def _from_dict(cls, d: dict):
    """Build a dataclass from a dict, ignoring unknown keys with a clear error
    instead of a raw TypeError from ``cls(**d)``."""
    if not isinstance(d, dict):
        raise ValueError(f"expected an object for {cls.__name__}, got {type(d).__name__}")
    known = {f.name for f in fields(cls)}
    unknown = set(d) - known
    if unknown:
        raise ValueError(f"{cls.__name__}: unknown field(s) {sorted(unknown)}")
    return cls(**d)


def load_agent(path: str) -> AgentTarget:
    with open(path) as f:
        return _from_dict(AgentTarget, json.load(f))


def load_targets(path: str) -> list[Target]:
    with open(path) as f:
        raw = json.load(f)
    if isinstance(raw, dict):
        raw = [raw]
    return [Target(**t) for t in raw]


def write_example(path: str) -> None:
    ex = [asdict(Target(
        name="vendor-under-test",
        base_url="https://api.vendor.example/v1",
        model="vendor-flagship-1",
        auth_value_env="VENDOR_API_KEY",
        proxy="http://127.0.0.1:8080",
        authorized=False,
        notes="Set authorized=true only with written test authorization.",
    ))]
    with open(path, "w") as f:
        json.dump(ex, f, indent=2)
