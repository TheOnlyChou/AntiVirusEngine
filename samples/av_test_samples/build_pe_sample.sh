#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
GOOS=windows GOARCH=amd64 go build -o sample_pe.exe pe_main.go
printf 'Built %s/sample_pe.exe\n' "$SCRIPT_DIR"
