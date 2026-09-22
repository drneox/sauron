#!/bin/bash
# Sauron ASM - Development startup script
# Prerequisite: PostgreSQL must be running first:
#   docker compose up -d db

set -e

BACKEND_PID=""
FRONTEND_PID=""

cleanup() {
  echo ""
  echo "Stopping services..."
  [ -n "$BACKEND_PID" ] && kill "$BACKEND_PID" 2>/dev/null || true
  [ -n "$FRONTEND_PID" ] && kill "$FRONTEND_PID" 2>/dev/null || true
  exit 0
}
trap cleanup INT TERM

echo "┌─────────────────────────────────────────┐"
echo "│          Sauron ASM - Starting up          │"
echo "└─────────────────────────────────────────┘"
echo ""

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Backend
echo "→ Starting FastAPI backend on :8000 ..."
cd "$ROOT_DIR/backend"
.venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000 --reload &
BACKEND_PID=$!

sleep 2

# Frontend
echo "→ Starting React frontend on :5173 ..."
cd "$ROOT_DIR/frontend"
npm run dev &
FRONTEND_PID=$!

echo ""
echo "✓ Backend:  http://localhost:8000"
echo "✓ Frontend: http://localhost:5173"
echo "✓ API Docs: http://localhost:8000/docs"
echo ""
echo "Press Ctrl+C to stop"

wait
