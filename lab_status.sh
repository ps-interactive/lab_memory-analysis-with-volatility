#!/bin/bash
echo "=========================================="
echo "         Lab Environment Status"
echo "=========================================="
echo ""
echo "Memory Dump:"
if [ -f "/evidence/infected_system.raw" ]; then
    echo "  [PASS] infected_system.raw found in /evidence/"
    echo "  Size: $(du -h /evidence/infected_system.raw | cut -f1)"
else
    echo "  [FAIL] Memory dump not found!"
fi
echo ""
echo "Volatility:"
if [ -x "/usr/local/bin/vol" ]; then
    echo "  [PASS] Volatility 3 installed and ready"
else
    echo "  [FAIL] Volatility not found!"
fi
echo ""
echo "Lab Files:"
if [ -d "/home/ubuntu/lab" ]; then
    echo "  [PASS] Lab files available in /home/ubuntu/lab/"
    echo "  Files: $(ls /home/ubuntu/lab/ | wc -l) files"
else
    echo "  [FAIL] Lab files not found!"
fi
echo ""
echo "Working Directory: $(pwd)"
echo "=========================================="
