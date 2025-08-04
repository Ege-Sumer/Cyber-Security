#!/bin/bash
echo "🚀 Installing CyberScan Pro..."

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 not found. Please install Python3 first."
    exit 1
fi

# Create requirements.txt if it doesn't exist
if [ ! -f requirements.txt ]; then
    echo "📄 Creating requirements.txt..."
    cat > requirements.txt << EOF
requests>=2.28.0
colorama>=0.4.4
EOF
fi

# Install requirements
echo "📦 Installing dependencies..."
pip3 install -r requirements.txt

# Make script executable
chmod +x cyberscan.py

echo "✅ Installation completed!"
echo "Usage: python3 cyberscan.py <target>"