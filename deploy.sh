#!/bin/bash

# ============================================================
# SHARANGA - DEPLOYMENT SCRIPT
# ============================================================

echo "🏹 SHARANGA - Deployment Script"
echo "================================"

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 not found. Installing..."
    sudo apt update && sudo apt install -y python3 python3-pip
fi

# Create virtual environment
echo "📦 Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Install dependencies
echo "📦 Installing dependencies..."
pip install -r requirements.txt

# Initialize database
echo "🗄️ Initializing database..."
python3 -c "from database import init_db; init_db()"

# Create folders
mkdir -p reports uploads

echo "✅ Deployment complete!"
echo "🌐 Run: python3 app.py"
echo "🔐 Default: admin / admin123"