#!/usr/bin/env bash
# Fetch real tokenizer vocabularies from llama.cpp's bundled GGUF files.
# No HuggingFace account or access required - these are plain files on GitHub.
set -euo pipefail
OUT=${1:-/tmp}
BASE=https://raw.githubusercontent.com/ggml-org/llama.cpp/master/models
for v in qwen2 deepseek-llm deepseek-coder llama-bpe gpt-2 phi-3 falcon \
         command-r starcoder refact mpt gpt-neox llama-spm bert-bge; do
  if curl -fsS -o "$OUT/v_$v.gguf" "$BASE/ggml-vocab-$v.gguf" 2>/dev/null; then
    echo "  ok   $v ($(stat -c%s "$OUT/v_$v.gguf" 2>/dev/null || stat -f%z "$OUT/v_$v.gguf") bytes)"
  else
    echo "  miss $v"
  fi
done
echo
echo "Now run:  python -m provenance_probe.tools.build_reference_from_gguf"
