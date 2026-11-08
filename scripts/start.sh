#!/usr/bin/env bash
# Build and start SPIDERS.Mk1 (http://127.0.0.1:8600).
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="$ROOT_DIR/.venv/bin/python"

if [[ ! -x "$PYTHON" ]]; then
  echo "Missing Python environment. Run scripts/setup.sh first." >&2
  exit 1
fi
if [[ ! -x "$ROOT_DIR/frontend/node_modules/.bin/vite" ]]; then
  echo "Missing frontend dependencies. Run npm install in frontend/ first." >&2
  exit 1
fi

npm --prefix "$ROOT_DIR/frontend" run build
cd "$ROOT_DIR/backend"
exec "$PYTHON" run.py
