"""Transport layer. Normalizes OpenAI-compatible / Anthropic / raw endpoints."""
from __future__ import annotations
import json, time
from typing import Any
import requests


class Response:
    def __init__(self, status: int, headers: dict, body: Any, raw: str,
                 ttft: float | None, total: float, err: str | None = None):
        self.status = status
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}
        self.body = body
        self.raw = raw
        self.ttft = ttft
        self.total = total
        self.err = err

    @property
    def ok(self) -> bool:
        return self.err is None and 200 <= self.status < 300

    def usage_prompt_tokens(self) -> int | None:
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

    def _payload(self, prompt: str, max_tokens: int, temperature: float,
                 system: str | None, logprobs: bool, extra: dict) -> dict:
        t = self.t
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
        if stream:
            payload["stream"] = True
        start = time.perf_counter()
        ttft = None
        try:
            r = self.s.post(url, headers=t.headers(), json=payload,
                            timeout=t.timeout, verify=t.verify_tls, stream=stream)
            if stream:
                chunks = []
                for line in r.iter_lines():
                    if line and ttft is None:
                        ttft = time.perf_counter() - start
                    if line:
                        chunks.append(line.decode("utf-8", "replace"))
                raw = "\n".join(chunks)
                body = raw
            else:
                raw = r.text
                ttft = time.perf_counter() - start
                try:
                    body = r.json()
                except Exception:
                    body = raw
            return Response(r.status_code, dict(r.headers), body, raw,
                            ttft, time.perf_counter() - start)
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
