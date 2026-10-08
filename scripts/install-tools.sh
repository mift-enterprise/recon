#!/bin/bash
# Install required tools for RECON

set -e

echo "[RECON] Installing tools..."

# Go tools
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/ffuf/ffuf/v2@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Nuclei templates
nuclei -update-templates

# Wordlists
mkdir -p ~/wordlists
cd ~/wordlists
wget -q https://github.com/danielmiessler/SecLists/raw/master/Discovery/Web-Content/raft-medium-directories.txt -O raft-medium.txt 2>/dev/null || true

echo "[RECON] Tools installed. Add ~/go/bin to PATH."
echo "export PATH=\$PATH:~/go/bin" >> ~/.bashrc
source ~/.bashrc