#!/usr/bin/env bash
# run.sh – activate the backend venv and start the FastAPI server
# Run from the project root:  bash backend/run.sh

set -e

BACKEND_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_PYTHON="$BACKEND_DIR/.venv/bin/python"

if [ ! -f "$VENV_PYTHON" ]; then
  echo "❌  venv not found. Run setup first:"
  echo "    bash backend/setup.sh"
  exit 1
fi

echo "==> Starting Network Intrusion Detection API..."
echo "    Docs: http://localhost:8000/docs"
echo ""

cd "$BACKEND_DIR"
"$VENV_PYTHON" main.py
