"""Transport layer. Normalizes OpenAI-compatible / Anthropic / raw / web-app
(template) endpoints."""
from __future__ import annotations
import copy, json, time
from typing import Any
import requests


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
        sse = stream or getattr(t, "stream_mode", "none") == "sse"
        delta_path = getattr(t, "stream_delta_path", "") or "choices.0.delta.content"
        if stream or sse:
            payload.setdefault("stream", True)
        start = time.perf_counter()
        ttft = None
        try:
            r = self.s.post(url, headers=t.headers(), json=payload,
                            timeout=t.timeout, verify=t.verify_tls, stream=sse)
            if sse:
                chunks, delta_text = [], []
                for line in r.iter_lines():
                    if line and ttft is None:
                        ttft = time.perf_counter() - start
                    if not line:
                        continue
                    s = line.decode("utf-8", "replace")
                    chunks.append(s)
                    if s.startswith("data:"):
                        payload_str = s[5:].strip()
                        if payload_str and payload_str != "[DONE]":
                            try:
                                piece = dig(json.loads(payload_str), delta_path)
                                if isinstance(piece, str):
                                    delta_text.append(piece)
                            except Exception:
                                pass
                raw = "\n".join(chunks)
                body = raw
                stream_text = "".join(delta_text) if delta_text else None
                return Response(r.status_code, dict(r.headers), body, raw, ttft,
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
            return Response(0, {}, None, "", None, time.perf_counter() - start, str(e))

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
            return Response(0, {}, None, "", None, time.perf_counter() - start, str(e))

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
            return Response(0, {}, None, "", None, time.perf_counter() - start, str(e))
