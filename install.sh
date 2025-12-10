#!/bin/bash
# Installation script for PCAP Analyzer

echo "================================================"
echo "PCAP Analyzer - Installation Script"
echo "================================================"
echo ""

# Check Python version
echo "Checking Python version..."
python_version=$(python3 --version 2>&1 | cut -d' ' -f2 | cut -d'.' -f1,2)
required_version="3.8"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then
    echo "❌ Error: Python 3.8 or higher is required"
    echo "   Current version: Python $python_version"
    exit 1
fi

echo "✓ Python $python_version detected"
echo ""

# Create virtual environment (optional but recommended)
echo "Creating virtual environment (optional)..."
read -p "Create virtual environment? (y/n) " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]
then
    python3 -m venv venv
    echo "✓ Virtual environment created"
    echo "  To activate: source venv/bin/activate"
    source venv/bin/activate
fi
echo ""

# Install dependencies
echo "Installing dependencies..."
pip install -r requirements.txt

if [ $? -eq 0 ]; then
    echo "✓ Dependencies installed successfully"
else
    echo "❌ Error installing dependencies"
    exit 1
fi
echo ""

# Create necessary directories
echo "Creating directories..."
mkdir -p logs
mkdir -p extracted_files
mkdir -p visualizations
mkdir -p reports
mkdir -p samples
echo "✓ Directories created"
echo ""

# Generate sample PCAP file
echo "Generating sample PCAP file..."
read -p "Generate sample traffic for testing? (y/n) " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]
then
    python3 tests/generate_sample_pcap.py
    echo "✓ Sample file generated: samples/sample_traffic.pcap"
fi
echo ""

# Test installation
echo "Testing installation..."
python3 -c "from core.parser import PCAPParser; print('✓ Core modules working')"
python3 -c "from PyQt5.QtWidgets import QApplication; print('✓ GUI modules working')"
echo ""

echo "================================================"
echo "Installation Complete!"
echo "================================================"
echo ""
echo "Quick Start:"
echo "  1. Launch GUI:        python pcap_analyzer.py"
echo "  2. Analyze file:      python pcap_analyzer.py -f samples/sample_traffic.pcap"
echo "  3. Get help:          python pcap_analyzer.py --help"
echo ""
echo "Documentation:"
echo "  - Quick Start:        QUICKSTART.md"
echo "  - User Manual:        docs/USER_MANUAL.md"
echo "  - Developer Guide:    docs/DEVELOPER_GUIDE.md"
echo ""
echo "Happy analyzing! 🎉"
