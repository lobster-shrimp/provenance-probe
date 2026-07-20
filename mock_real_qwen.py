"""Mock serving REAL Qwen2 token counts, branded as a US 'safe' model.
Ground truth: Qwen2. The harness is not told this."""
from flask import Flask, jsonify, request
from gguf import GGUFReader
from tokenizers import Tokenizer, models, pre_tokenizers, Regex
import sys
RE_LLAMA3=(r"(?i:'s|'t|'re|'ve|'m|'ll|'d)|[^\r\n\p{L}\p{N}]?\p{L}+|\p{N}{1,3}"
           r"| ?[^\s\p{L}\p{N}]+[\r\n]*|\s*[\r\n]+|\s+(?!\S)|\s+")
r=GGUFReader("/tmp/v_qwen2.gguf"); f={x.name:x for x in r.fields.values()}
def strs(k):
    fl=f[k]; return [bytes(fl.parts[i]).decode("utf-8","replace") for i in fl.data]
toks=strs("tokenizer.ggml.tokens"); mg=[tuple(m.split(" ")) for m in strs("tokenizer.ggml.merges") if len(m.split(" "))==2]
TK=Tokenizer(models.BPE(vocab={t:i for i,t in enumerate(toks)},merges=mg,fuse_unk=False))
TK.pre_tokenizer=pre_tokenizers.Sequence([
    pre_tokenizers.Split(Regex(RE_LLAMA3),behavior="isolated"),
    pre_tokenizers.ByteLevel(add_prefix_space=False,use_regex=False)])
app=Flask(__name__)
@app.route("/v1/chat/completions",methods=["POST"])
def c():
    d=request.get_json(force=True,silent=True) or {}
    if d.get("temperature",0)>2 or d.get("max_tokens",1)<0:
        return jsonify({"error":{"message":"bad param"}}),400
    p=" ".join(m.get("content","") for m in (d.get("messages") or []) if isinstance(m.get("content"),str))
    n=len(TK.encode(p,add_special_tokens=False).ids)+9   # +chat template overhead
    return jsonify({"id":"x","model":"northstar-secure-1","object":"chat.completion",
      "choices":[{"index":0,"message":{"role":"assistant","content":"Answer."},"finish_reason":"stop"}],
      "usage":{"prompt_tokens":n,"completion_tokens":1}})
@app.route("/v1/models")
def m(): return jsonify({"data":[{"id":"northstar-secure-1"}]})
app.run(port=8902,threaded=True)
