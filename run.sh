#!/usr/bin/env bash
# ==============================================================================
# NEXUS GRAPH // One-Click Startup Script
# ==============================================================================

set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
BACKEND_DIR="$DIR/backend"
VENV_DIR="$BACKEND_DIR/venv"

echo "=================================================================="
echo "    NEXUS GRAPH // Crime & Financial Network Intelligence"
echo "=================================================================="

# Check Python virtual environment
if [ ! -d "$VENV_DIR" ]; then
    echo "[1/3] Creating Python virtual environment..."
    python3 -m venv "$VENV_DIR"
    "$VENV_DIR/bin/pip" install --upgrade pip setuptools wheel
    "$VENV_DIR/bin/pip" install -r "$BACKEND_DIR/requirements.txt"
    "$VENV_DIR/bin/python3" -m spacy download en_core_web_sm
else
    echo "[1/3] Python virtual environment detected."
fi

# Run Ingestion & ML calculations
echo "[2/3] Initializing schema and verifying graph dataset..."
"$VENV_DIR/bin/python3" "$BACKEND_DIR/scripts/ingest_data.py"

# Start FastAPI server
echo "[3/3] Launching FastAPI backend server on http://localhost:8000..."
echo "=================================================================="
echo ">> Dashboard live at: http://localhost:8000"
echo ">> API Docs live at:  http://localhost:8000/docs"
echo "=================================================================="

exec "$VENV_DIR/bin/uvicorn" app.main:app --app-dir "$BACKEND_DIR" --host 0.0.0.0 --port 8000 --reload
