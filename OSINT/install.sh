#!/bin/bash
echo "🕵️ Installing OSINT Hunter Pro..."

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
beautifulsoup4>=4.11.0
colorama>=0.4.4
python-whois>=0.7.3
dnspython>=2.2.0
lxml>=4.9.0
EOF
fi

# Install requirements
echo "📦 Installing dependencies..."
pip3 install -r requirements.txt

# Make script executable
chmod +x osint_hunter.py

echo "✅ Installation completed!"
echo ""
echo "Usage examples:"
echo "  python3 osint_hunter.py example.com"
echo "  python3 osint_hunter.py company_name -t social"
echo "  python3 osint_hunter.py example.com -m domain,emails,social"