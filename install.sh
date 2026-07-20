#!/usr/bin/env bash
# Local install. Creates a venv, installs the package, launches the UI.
set -euo pipefail
cd "$(dirname "$0")"

PY=${PYTHON:-python3}
$PY -c 'import sys; assert sys.version_info>=(3,10)' || { echo "Python 3.10+ required"; exit 1; }

echo "==> creating venv (.venv)"
$PY -m venv .venv
. .venv/bin/activate
pip install --upgrade pip -q

echo "==> installing provenance-probe"
pip install -e . -q

echo "==> installing reference-tokenizer extras (optional, large)"
pip install -e '.[reference]' -q || echo "    [skip] extras failed - tokenizer layer will be inert until you run build-reference"

echo "==> building tokenizer reference vectors"
provenance-probe build-reference || echo "    [skip] no HuggingFace access; run 'provenance-probe build-reference' later"

cat <<'MSG'

Installed. Activate with:  source .venv/bin/activate

  provenance-probe serve                 # web UI on http://127.0.0.1:8770
  provenance-probe assess --config targets.json
  provenance-probe clientsrc --url https://app.example
  provenance-probe artifacts /path/to/model

MSG
