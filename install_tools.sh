#!/usr/bin/env bash
set -euo pipefail

# install_tools.sh - Installs common pentest tools (Kali/Debian)
# Run as root: sudo ./install_tools.sh

RECOMMENDED=(amass subfinder assetfinder gobuster masscan nmap sslscan whatweb nikto wpscan sqlmap aquatone gowitness nuclei lynis hydra medusa msfconsole jq curl)

echo "[INFO] Updating package lists..."
apt update -y

echo "[INFO] Installing recommended packages (may take a while)..."
apt install -y "${RECOMMENDED[@]}" || {
  echo "[WARN] Some packages failed to install. Install missing ones manually."
}

echo "[INFO] Installing Go tools (if go is present) for subfinder/assetfinder optional installs..."
if command -v go >/dev/null 2>&1; then
  if ! command -v subfinder >/dev/null 2>&1; then
    echo "[INFO] Installing subfinder via 'go install' (may require GOPATH/bin in PATH)"
    GO111MODULE=on go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest || true
  fi
  if ! command -v assetfinder >/dev/null 2>&1; then
    echo "[INFO] Installing assetfinder via 'go install'"
    go install github.com/tomnomnom/assetfinder@latest || true
  fi
fi

echo "[INFO] Installation step complete. Note: some tools (wpscan, msfconsole, wpscan-db) may require extra setup per their docs."
