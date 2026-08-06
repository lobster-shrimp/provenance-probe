"""Transport layer. Normalizes OpenAI-compatible / Anthropic / raw / web-app
(template) endpoints."""
from __future__ import annotations
import copy, json, time
from typing import Any
import requests

from . import egress

# Cap accumulated bytes from a streamed response so a hostile/endless stream from
# an untrusted target can't OOM the probe (review #44).
_STREAM_MAX_BYTES = 8_000_000


def dig(obj: Any, path: str):
    """Read a value by dotted path with numeric indices, e.g.
    'choices.0.message.content'. Returns None if any hop is missing."""
    if not path:
        return None
    cur = obj
    for part in path.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        elif isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return cur


def parse_jsonline_delta(line: str, delta_path: str = "choices.0.delta.content") -> str | None:
    """Extract incremental text from one bare JSON-lines frame (no `data:` prefix).
    Mirrors parse_sse_delta for newline-delimited-JSON streams (e.g. v0.app)."""
    line = line.strip()
    if not line or line == "[DONE]":
        return None
    try:
        piece = dig(json.loads(line), delta_path)
        return piece if isinstance(piece, str) else None
    except Exception:
        return None


def parse_sse_delta(line: str, delta_path: str = "choices.0.delta.content") -> str | None:
    """Extract the incremental text from one SSE `data:` line, or None. Shared by
    the streaming client read and the sentinel proxy tee so there is ONE
    `data:`/`[DONE]` parser."""
    if not line.startswith("data:"):
        return None
    payload = line[5:].strip()
    if not payload or payload == "[DONE]":
        return None
    try:
        piece = dig(json.loads(payload), delta_path)
        return piece if isinstance(piece, str) else None
    except Exception:
        return None


def _substitute(node: Any, repl: dict) -> Any:
    """Deep-copy a request template, replacing __PLACEHOLDER__ tokens in strings."""
    if isinstance(node, str):
        out = node
        for k, v in repl.items():
            if out == k:            # whole-value replacement preserves non-string types
                return v
            out = out.replace(k, str(v))
        return out
    if isinstance(node, dict):
        return {k: _substitute(v, repl) for k, v in node.items()}
    if isinstance(node, list):
        return [_substitute(v, repl) for v in node]
    return node


class Response:
    def __init__(self, status: int, headers: dict, body: Any, raw: str,
                 ttft: float | None, total: float, err: str | None = None,
                 paths: dict | None = None, stream_text: str | None = None):
        self.status = status
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}
        self.body = body
        self.raw = raw
        self.ttft = ttft
        self.total = total
        self.err = err
        # Configured response paths (web-app template mode) + any text already
        # accumulated from an SSE stream.
        self.paths = paths or {}
        self.stream_text = stream_text

    @property
    def ok(self) -> bool:
        return self.err is None and 200 <= self.status < 300

    def usage_prompt_tokens(self) -> int | None:
        p = self.paths.get("prompt_tokens")
        if p:
            v = dig(self.body, p)
            return v if isinstance(v, int) else None
        b = self.body
        if not isinstance(b, dict):
            return None
        u = b.get("usage") or {}
        for k in ("prompt_tokens", "input_tokens", "promptTokens"):
            if isinstance(u.get(k), int):
                return u[k]
        for k in ("prompt_tokens", "input_tokens"):
            if isinstance(b.get(k), int):
                return b[k]
        return None

    def text(self) -> str:
        if self.stream_text is not None:
            return self.stream_text
        p = self.paths.get("text")
        if p:
            v = dig(self.body, p)
            if isinstance(v, str):
                return v
        b = self.body
        if not isinstance(b, dict):
            return self.raw or ""
        try:
            ch = b.get("choices")
            if ch:
                m = ch[0].get("message") or {}
                if isinstance(m.get("content"), str):
                    return m["content"]
                if ch[0].get("text"):
                    return ch[0]["text"]
            c = b.get("content")
            if isinstance(c, list):
                return "".join(p.get("text", "") for p in c if isinstance(p, dict))
        except Exception:
            pass
        return self.raw or ""

    def echoed_model(self) -> str | None:
        p = self.paths.get("model")
        if p:
            v = dig(self.body, p)
            if isinstance(v, str):
                return v
        b = self.body
        if isinstance(b, dict):
            for k in ("model", "model_id", "modelId"):
                if isinstance(b.get(k), str):
                    return b[k]
        return None


class Client:
    def __init__(self, target):
        self.t = target
        self.s = requests.Session()
        if target.proxy:
            self.s.proxies = {"http": target.proxy, "https": target.proxy}
        # Public-hosting mode only (env-gated, OFF by default): mount the SSRF
        # egress guard on the shared session so chat/retry/raw_post/list_models
        # and redirects all validate + pin the connect target. Byte-identical to
        # stock requests when the flag is unset.
        if egress.guard_enabled():
            egress.install_guard(self.s)

    def _safe_err(self, msg: str) -> str:
        """Redact any credential-bearing header value from a transport error string
        before it becomes ``Response.err``.

        Defense-in-depth for the leak closed at its root in ``Target.headers()``:
        ``Response.err`` is persisted into the report bundle and served by
        ``/report/<name>``, so it must never echo an auth token or session cookie —
        even if some future ``requests`` exception embeds a header value. The
        always-safe headers (content negotiation / API version) are left intact."""
        try:
            for k, v in self.t.headers().items():
                if k in ("Content-Type", "Accept", "anthropic-version"):
                    continue
                if isinstance(v, str) and len(v) >= 4 and v in msg:
                    msg = msg.replace(v, "[redacted]")
        except Exception:
            pass
        return msg

    def _paths(self) -> dict:
        t = self.t
        return {"text": getattr(t, "response_text_path", ""),
                "prompt_tokens": getattr(t, "response_prompt_tokens_path", ""),
                "model": getattr(t, "response_model_path", "")}

    def _payload(self, prompt: str, max_tokens: int, temperature: float,
                 system: str | None, logprobs: bool, extra: dict) -> dict:
        t = self.t
        if t.api_style == "template" and getattr(t, "request_template", None):
            repl = {"__PROMPT__": prompt, "__MAX_TOKENS__": max_tokens,
                    "__TEMPERATURE__": temperature, "__SYSTEM__": system or ""}
            p = _substitute(copy.deepcopy(t.request_template), repl)
            p.update(extra or {})
            return p
        if t.api_style == "anthropic":
            p: dict[str, Any] = {"model": t.model, "max_tokens": max_tokens,
                                 "temperature": temperature,
                                 "messages": [{"role": "user", "content": prompt}]}
            if system:
                p["system"] = system
        else:
            msgs = []
            if system:
                msgs.append({"role": "system", "content": system})
            msgs.append({"role": "user", "content": prompt})
            p = {"model": t.model, "messages": msgs,
                 "max_tokens": max_tokens, "temperature": temperature}
            if logprobs:
                p["logprobs"] = True
                p["top_logprobs"] = 5
        p.update(extra or {})
        return p

    def chat(self, prompt: str, *, max_tokens: int = 1, temperature: float = 0.0,
             system: str | None = None, logprobs: bool = False,
             extra: dict | None = None, stream: bool = False) -> Response:
        t = self.t
        url = t.url(t.chat_path)
        payload = self._payload(prompt, max_tokens, temperature, system, logprobs, extra or {})
        paths = self._paths()
        # Web-app template endpoints may stream Server-Sent Events; accumulate
        # the per-chunk text delta so the behavioral layers get the full reply.
        stream_mode = getattr(t, "stream_mode", "none")
        sse = stream or stream_mode in ("sse", "jsonlines")
        delta_path = getattr(t, "stream_delta_path", "") or "choices.0.delta.content"
        # Template targets replay the captured body verbatim — never inject a
        # `stream` field the app didn't send (would break replay on custom apps).
        if sse and t.api_style != "template":       # never inject `stream` into a verbatim template replay
            payload.setdefault("stream", True)
        start = time.perf_counter()
        ttft = None
        try:
            r = self.s.post(url, headers=t.headers(), json=payload,
                            timeout=t.timeout, verify=t.verify_tls, stream=sse)
            if sse:
                chunks, delta_text, total = [], [], 0
                for line in r.iter_lines():
                    if line and ttft is None:
                        ttft = time.perf_counter() - start
                    if not line:
                        continue
                    total += len(line)
                    if total > _STREAM_MAX_BYTES:    # bound a hostile/endless stream (review #44)
                        break
                    s = line.decode("utf-8", "replace")
                    chunks.append(s)
                    piece = (parse_jsonline_delta(s, delta_path) if stream_mode == "jsonlines"
                             else parse_sse_delta(s, delta_path))
                    if piece:
                        delta_text.append(piece)
                raw = "\n".join(chunks)
                stream_text = "".join(delta_text) if delta_text else None
                # No delta matched -> the configured delta path doesn't fit this
                # stream. Don't hand the raw framed protocol text back as a "reply"
                # (dry_run would false-pass and save a broken target, review #44).
                # Try a plain-JSON fallback, else surface an error so ok=False.
                if stream_text is None:
                    try:
                        return Response(r.status_code, dict(r.headers), json.loads(raw),
                                        raw, ttft, time.perf_counter() - start, paths=paths)
                    except Exception:
                        return Response(r.status_code, dict(r.headers), None, raw, ttft,
                                        time.perf_counter() - start,
                                        err="stream produced no reply via the delta path "
                                            f"'{delta_path}'", paths=paths)
                return Response(r.status_code, dict(r.headers), raw, raw, ttft,
                                time.perf_counter() - start, paths=paths,
                                stream_text=stream_text)
            raw = r.text
            # Reasoning models (Moonshot kimi, OpenAI o-series, ...) reject
            # temperature=0 with a 400. prompt_tokens is deterministic
            # regardless of temperature, so retry once without it — this keeps
            # the tokenizer layer working against reasoning endpoints.
            if (r.status_code == 400 and isinstance(payload, dict)
                    and "temperature" in payload and "temperature" in raw.lower()):
                retry = {k: v for k, v in payload.items() if k != "temperature"}
                r = self.s.post(url, headers=t.headers(), json=retry,
                                timeout=t.timeout, verify=t.verify_tls)
                raw = r.text
            ttft = time.perf_counter() - start
            try:
                body = r.json()
            except Exception:
                body = raw
            return Response(r.status_code, dict(r.headers), body, raw,
                            ttft, time.perf_counter() - start, paths=paths)
        except Exception as e:
            return Response(0, {}, None, "", None, time.perf_counter() - start, self._safe_err(str(e)))

    def raw_post(self, path: str, payload: dict) -> Response:
        t = self.t
        start = time.perf_counter()
        try:
            r = self.s.post(t.url(path), headers=t.headers(), json=payload,
                            timeout=t.timeout, verify=t.verify_tls)
            try:
                body = r.json()
            except Exception:
                body = r.text
            return Response(r.status_code, dict(r.headers), body, r.text,
                            None, time.perf_counter() - start)
        except Exception as e:
            return Response(0, {}, None, "", None, time.perf_counter() - start, self._safe_err(str(e)))

    def list_models(self) -> Response:
        t = self.t
        start = time.perf_counter()
        try:
            r = self.s.get(t.url(t.models_path), headers=t.headers(),
                           timeout=t.timeout, verify=t.verify_tls)
            try:
                body = r.json()
            except Exception:
                body = r.text
            return Response(r.status_code, dict(r.headers), body, r.text,
                            None, time.perf_counter() - start)
        except Exception as e:
            return Response(0, {}, None, "", None, time.perf_counter() - start, self._safe_err(str(e)))
