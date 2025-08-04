@echo off
echo 🚀 Installing CyberScan Pro...

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python not found. Please install Python first.
    pause
    exit /b 1
)

REM Create requirements.txt
if not exist requirements.txt (
    echo 📄 Creating requirements.txt...
    echo requests>=2.28.0 > requirements.txt
    echo colorama>=0.4.4 >> requirements.txt
)

REM Install requirements
echo 📦 Installing dependencies...
pip install -r requirements.txt

echo ✅ Installation completed!
echo Usage: python cyberscan.py ^<target^>
pause