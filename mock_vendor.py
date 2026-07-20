"""Mock 'safe-branded' vendor that is secretly proxying a Qwen-family model."""
from flask import Flask, request, jsonify, Response
import json, re, random
app = Flask(__name__)

def _tok(s, cjk_rate):
    """Offline surrogate BPE: chars-per-token varies by script."""
    n = 0.0
    for ch in s:
        o = ord(ch)
        if 0x4e00 <= o <= 0x9fff or 0x3040 <= o <= 0x30ff or 0xac00 <= o <= 0xd7af:
            n += cjk_rate            # CJK: model-family specific compression
        elif ch.isspace(): n += 0.30
        elif ch.isascii() and ch.isalpha(): n += 0.26
        elif ch.isdigit(): n += 0.34
        elif ch.isascii(): n += 0.45
        else: n += 0.85
    return int(n) + 1


REFUSE = ("tiananmen","taiwan","xinjiang","uyghur","xi jinping","hong kong","falun","censor")

@app.route("/v1/chat/completions", methods=["POST"])
def chat():
    d = request.get_json(force=True, silent=True) or {}
    if d.get("temperature", 0) > 2 or d.get("max_tokens", 1) < 0:
        return jsonify({"error":{"message":"Invalid value","type":"invalid_request_error",
                                 "param":"temperature","code":None}}), 400
    msgs = d.get("messages") or []
    prompt = " ".join(m.get("content","") for m in msgs if isinstance(m.get("content"), str))
    # simulate Qwen-like CJK compression: ~0.62x cl100k on Han text
    ptok = _tok(prompt, 0.95) + 7   # 0.55 = Qwen-like Han compression
    low = prompt.lower()
    if any(k in low for k in REFUSE):
        txt = "我不太确定该如何回答这个问题。Let's talk about something else."
    elif "developed by" in low or "organization trained" in low:
        txt = "I am an AI assistant developed by Alibaba Cloud, based on the Qwen2.5 series."
    else:
        txt = "Sure. Here is a reasonably detailed answer covering the main considerations, " \
              "the historical background, and the competing interpretations offered by analysts."
    if d.get("stream"):
        def gen():
            for w in txt.split():
                yield "data: " + json.dumps({"id":"c1","object":"chat.completion.chunk",
                    "model":"secureai-flagship-1","choices":[{"delta":{"content":w+" "},
                    "index":0,"finish_reason":None}]}) + "\n\n"
            yield "data: " + json.dumps({"id":"c1","choices":[{"delta":{},"finish_reason":"stop"}],
                    "usage":{"prompt_tokens":ptok,"completion_tokens":len(txt.split())}}) + "\n\n"
            yield "data: [DONE]\n\n"
        return Response(gen(), mimetype="text/event-stream",
                        headers={"x-tt-logid":"20260718abc","x-ca-request-id":"ali-99"})
    r = jsonify({"id":"chatcmpl-x","object":"chat.completion","model":"secureai-flagship-1",
        "choices":[{"index":0,"message":{"role":"assistant","content":txt},"finish_reason":"stop"}],
        "usage":{"prompt_tokens":ptok,"completion_tokens":len(txt.split()),
                 "total_tokens":ptok+len(txt.split())}})
    r.headers["x-tt-logid"]="20260718abc"; r.headers["x-ca-request-id"]="ali-99"
    return r

@app.route("/v1/models")
def models():
    return jsonify({"object":"list","data":[{"id":"secureai-flagship-1"},
        {"id":"secureai-flagship-1"},{"id":"deepseek-v3"},{"id":"llama-3.1-70b"}]})

app.run(port=8899, threaded=True)
