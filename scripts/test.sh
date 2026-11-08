#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
(cd backend && PYTHONPATH=. ../.venv/bin/python -m pytest -q)
(cd frontend && npx tsc -p tsconfig.json)
echo "All checks passed."
