#!/usr/bin/env bash
# One-time setup: Python venv + backend deps + frontend build.
set -euo pipefail
cd "$(dirname "$0")/.."
PY=${PYTHON:-python3}
[ -d .venv ] || "$PY" -m venv .venv
.venv/bin/pip install -q --upgrade pip
.venv/bin/pip install -q -r backend/requirements.txt
(cd frontend && npm install --silent && npm run build)
echo "Setup complete. Start with: scripts/start.sh"
