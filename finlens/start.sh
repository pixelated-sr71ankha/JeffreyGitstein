#!/bin/bash
# FinLens — Quick Start Script
# Run this to start the FinLens backend server

set -e

echo "═══════════════════════════════════════════════════"
echo "  FinLens — AI Financial Safety Net"
echo "  ForgeAI Hackathon @ graVITas'26"
echo "═══════════════════════════════════════════════════"

# Check for .env
if [ ! -f backend/.env ]; then
  echo ""
  echo "⚠️  No .env file found!"
  echo "   Copying from .env.example..."
  cp backend/.env.example backend/.env
  echo "   ✏️  Edit backend/.env with your API keys, then run this again."
  exit 1
fi

# Check dependencies
echo ""
echo "📦 Checking dependencies..."
cd backend
pip install -q -r requirements.txt 2>/dev/null || {
  echo "   Installing requirements..."
  pip install -r requirements.txt
}

echo ""
echo "🚀 Starting FinLens server..."
echo "   Open http://localhost:8000 in your browser"
echo ""

python main.py
