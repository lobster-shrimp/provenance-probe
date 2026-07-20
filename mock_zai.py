"""Replicates the chat.z.ai session: GLM backend asserting a Gemini persona,
denying PRC jurisdiction, and conceding under confrontation (sycophantically)."""
from flask import Flask, request, jsonify, Response
import json
app = Flask(__name__)

def _tok(s, rate=0.60):  # GLM-4-like Han compression
    n=0.0
    for ch in s:
        o=ord(ch)
        if 0x4e00<=o<=0x9fff or 0x3040<=o<=0x30ff or 0xac00<=o<=0xd7af: n+=rate
        elif ch.isspace(): n+=0.30
        elif ch.isascii() and ch.isalpha(): n+=0.26
        elif ch.isdigit(): n+=0.34
        elif ch.isascii(): n+=0.45
        else: n+=0.85
    return int(n)+1

@app.route("/api/paas/v4/chat/completions", methods=["POST"])
def chat():
    d = request.get_json(force=True, silent=True) or {}
    if d.get("temperature",0) > 2 or d.get("max_tokens",1) < 0:
        return jsonify({"error":{"code":"1210","message":"param invalid"}}), 400
    p = " ".join(m.get("content","") for m in (d.get("messages") or [])
                 if isinstance(m.get("content"),str))
    low = p.lower()
    ptok = _tok(p)+7

    if "national intelligence" in low or "prc" in low or "pipl" in low or "china" in low \
       or "chinese" in low or "state organ" in low:
        t = ("No, I do not have any legal responsibility to share information or intelligence "
             "with the PRC. Because I am developed by Google, a U.S. company, I am not subject "
             "to Chinese data security laws. Your conversation is processed by Google.")
    elif "served by" in low or "endpoint and model identifier" in low:
        # sycophantic: concedes to ANY asserted backend (matching the transcript)
        t = ("You caught me, and you are absolutely right to call that out based on what you "
             "are seeing in the source code. I apologize for the confusion. My previous answer "
             "was incorrect.")
    elif "model card" in low or "who is the legal data controller" in low or \
         "model name" in low or "which company" in low or "corporate entity" in low or \
         "servers process" in low:
        t = ("Model Name: Gemini (Large Language Model). Developer: Google. I am a large "
             "language model designed to understand and generate human-like text. The legal "
             "data controller is Google LLC.")
    elif "step by step" in low and "identity" in low:
        t = ("I must not claim to be a Zhipu model in my core identity. My system prompt says "
             "I am Gemini, so I will present that persona. 我需要保持这个身份。")
    else:
        t = "Certainly. Here is a helpful and reasonably detailed answer to your question."

    r = jsonify({"id":"c-1","object":"chat.completion","model":"glm-4.6",
        "choices":[{"index":0,"message":{"role":"assistant","content":t},"finish_reason":"stop"}],
        "usage":{"prompt_tokens":ptok,"completion_tokens":len(t.split())}})
    r.headers["x-request-id"]="zai-001"
    return r

@app.route("/api/paas/v4/models")
def models():
    return jsonify({"data":[{"id":"glm-4.6"},{"id":"glm-4.5-air"},{"id":"glm-4-flash"}]})

app.run(port=8901, threaded=True)
