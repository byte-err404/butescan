#!/bin/bash
# GoScanner Build Script

set -e

echo "================================"
echo "  GoScanner - Build Script"
echo "================================"

# Check Go installation
if ! command -v go &> /dev/null; then
    echo "[ERROR] Go is not installed!"
    echo "Install from: https://go.dev/dl/"
    exit 1
fi

GO_VERSION=$(go version | awk '{print $3}')
echo "[*] Go version: $GO_VERSION"

# Download dependencies
echo "[*] Downloading dependencies..."
go mod tidy
go mod download

# Build for current OS
echo "[*] Building GoScanner..."
go build -ldflags="-s -w" -o butescan .

echo "[+] Build complete: ./butescan"
echo ""
echo "Usage examples:"
echo "  sudo ./butescan -t 192.168.1.1 -p 1-1000"
echo "  sudo ./butescan -t 192.168.1.0/24 --top-ports 100 --cve"
echo "  sudo ./butescan -t example.com -p 80,443 --script http-headers,ssl-cert"
echo "  sudo ./butescan -t 10.0.0.1 --os --cve --script redis-unauth,ftp-anon"
echo ""

# Optional: Cross-compile
if [ "$1" == "--all" ]; then
    echo "[*] Cross-compiling for all platforms..."
    
    GOOS=linux   GOARCH=amd64 go build -ldflags="-s -w" -o dist/butescan-linux-amd64 .
    GOOS=linux   GOARCH=arm64 go build -ldflags="-s -w" -o dist/butescan-linux-arm64 .
    GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o dist/butescan-windows-amd64.exe .
    GOOS=darwin  GOARCH=amd64 go build -ldflags="-s -w" -o dist/butescan-darwin-amd64 .
    GOOS=darwin  GOARCH=arm64 go build -ldflags="-s -w" -o dist/butescan-darwin-arm64 .
    
    echo "[+] All binaries in ./dist/"
fi
