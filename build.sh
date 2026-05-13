#!/bin/bash

# ============================================
# Butescan - Advanced Network Scanner
# Build & Cross-Compile Script
# ============================================

set -e

echo "=========================================="
echo "   ⚡ Butescan - Build Script"
echo "=========================================="

# Check Go installation
if ! command -v go &> /dev/null; then
    echo "[ERROR] Go is not installed!"
    echo "[INFO] Install Go from: https://go.dev/dl/"
    exit 1
fi

GO_VERSION=$(go version | awk '{print $3}')

echo "[*] Detected Go version: $GO_VERSION"
echo ""

# Create dist directory
mkdir -p dist

# Download dependencies
echo "[*] Downloading dependencies..."
go mod tidy
go mod download

echo ""

# Build native binary
echo "[*] Building Butescan for current platform..."

go build \
    -trimpath \
    -ldflags="-s -w" \
    -o butescan .

echo ""
echo "[+] Build completed successfully!"
echo "[+] Binary: ./butescan"

# Binary info
if command -v file &> /dev/null; then
    echo ""
    echo "[*] Binary information:"
    file butescan
fi

echo ""
echo "=========================================="
echo " Usage Examples"
echo "=========================================="

echo ""
echo "[1] Basic Scan"
echo "  sudo ./butescan -t 192.168.1.1"

echo ""
echo "[2] Full Port Scan"
echo "  sudo ./butescan -t 192.168.1.1 -p 1-65535"

echo ""
echo "[3] SYN Scan"
echo "  sudo ./butescan -t 192.168.1.1 -sS"

echo ""
echo "[4] UDP Scan"
echo "  sudo ./butescan -t 192.168.1.1 -sU -p 53,161"

echo ""
echo "[5] Aggressive Scan"
echo "  sudo ./butescan -t 192.168.1.1 -A"

echo ""
echo "[6] Subnet Scan"
echo "  sudo ./butescan -t 192.168.1.0/24 --top-ports 100"

echo ""
echo "[7] CVE + OS Detection"
echo "  sudo ./butescan -t 10.0.0.5 --cve -O"

echo ""
echo "[8] Script Engine"
echo "  sudo ./butescan -t example.com -p 80,443 --script http-headers,ssl-cert"

echo ""
echo "[9] Save JSON Report"
echo "  sudo ./butescan -t 192.168.1.1 --format json -o scan.json"

echo ""
echo "=========================================="
echo " Notes"
echo "=========================================="

echo ""
echo " • SYN scans require root privileges"
echo " • UDP scans are significantly slower"
echo " • CVE lookups may be rate-limited"
echo ""

# Cross Compile
if [ "$1" == "--all" ]; then

    echo "=========================================="
    echo " Cross Compiling"
    echo "=========================================="

    mkdir -p dist

    echo "[*] Building Linux AMD64..."
    GOOS=linux GOARCH=amd64 \
        go build -trimpath -ldflags="-s -w" \
        -o dist/butescan-linux-amd64 .

    echo "[*] Building Linux ARM64..."
    GOOS=linux GOARCH=arm64 \
        go build -trimpath -ldflags="-s -w" \
        -o dist/butescan-linux-arm64 .

    echo "[*] Building Windows AMD64..."
    GOOS=windows GOARCH=amd64 \
        go build -trimpath -ldflags="-s -w" \
        -o dist/butescan-windows-amd64.exe .

    echo "[*] Building macOS AMD64..."
    GOOS=darwin GOARCH=amd64 \
        go build -trimpath -ldflags="-s -w" \
        -o dist/butescan-darwin-amd64 .

    echo "[*] Building macOS ARM64..."
    GOOS=darwin GOARCH=arm64 \
        go build -trimpath -ldflags="-s -w" \
        -o dist/butescan-darwin-arm64 .

    echo ""
    echo "[+] Cross compilation complete!"
    echo "[+] Binaries saved in ./dist/"
fi

echo ""
echo "=========================================="
echo " Build Finished"
echo "=========================================="
