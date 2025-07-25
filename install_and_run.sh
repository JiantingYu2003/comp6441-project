#!/bin/bash

echo "Secure Chat System - Installation and Startup Script"
echo "====================================="

# Check Python version
echo "Checking Python version..."
python3 --version
if [ $? -ne 0 ]; then
    echo "Error: Please install Python 3 first"
    exit 1
fi

# Check pip
echo "Checking pip..."
pip3 --version
if [ $? -ne 0 ]; then
    echo "Error: Please install pip3 first"
    exit 1
fi

# Install dependencies
echo "Installing Python dependencies..."
pip3 install -r requirements.txt
if [ $? -ne 0 ]; then
    echo "Dependency installation failed"
    exit 1
fi

# Check port usage
echo "Checking port usage..."
if lsof -i :8080 > /dev/null 2>&1; then
    echo "Port 8080 is occupied, cleaning up..."
    pkill -9 -f "python.*app.py" 2>/dev/null || true
    sleep 2
fi

# Clear cache
echo "Clearing Python cache..."
find . -name "*.pyc" -delete 2>/dev/null || true
find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true

# Start server
echo "Starting secure chat system..."
echo "====================================="
echo "Installation complete!"
echo "Access URL: http://127.0.0.1:8080"
echo "Recommend using incognito mode for best experience"
echo "Press Ctrl+C to stop server"
echo "====================================="

# Start application
python3 app.py 