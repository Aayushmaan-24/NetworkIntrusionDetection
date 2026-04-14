#!/usr/bin/env bash
# setup.sh – create a venv and install backend dependencies
# Run from the project root:  bash backend/setup.sh

set -e

BACKEND_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="$BACKEND_DIR/.venv"

echo "==> Creating virtual environment at $VENV_DIR ..."
python3 -m venv "$VENV_DIR"

echo "==> Activating venv and installing dependencies ..."
"$VENV_DIR/bin/pip" install --upgrade pip
"$VENV_DIR/bin/pip" install -r "$BACKEND_DIR/requirements.txt"

echo ""
echo "✅  Setup complete!"
echo ""
echo "To start the backend:"
echo "  bash backend/run.sh"
echo ""
echo "Or activate manually:"
echo "  source backend/.venv/bin/activate"
echo "  python backend/main.py"
