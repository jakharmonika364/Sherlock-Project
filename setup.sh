#!/usr/bin/env bash
set -euo pipefail

# Decompress block fixtures
for f in fixtures/*.gz; do
    echo "Decompressing $f (forcing)..."
    gunzip -kf "$f"
done

# Find go binary
if ! command -v go &>/dev/null; then
    go_path=$(where.exe go 2>/dev/null | head -n1) || true
    if [[ -n "$go_path" ]]; then
        # Convert path for bash
        drive=$(echo "${go_path:0:1}" | tr '[:upper:]' '[:lower:]')
        rest=$(echo "${win_path:="${go_path:3}"}" | tr '\\' '/')
        if [[ -d "/mnt/host/${drive}" ]]; then
            go_dir=$(dirname "/mnt/host/${drive}/${rest}")
        elif [[ -d "/mnt/${drive}" ]]; then
            go_dir=$(dirname "/mnt/${drive}/${rest}")
        else
            go_dir=$(dirname "/${drive}/${rest}")
        fi
        export PATH="$go_dir:$PATH"
    fi
fi

# Re-check and build
GO_BIN="go"
if ! command -v go &>/dev/null; then
    if command -v go.exe &>/dev/null; then
        GO_BIN="go.exe"
    else
        echo "Error: go not found in PATH" >&2
        exit 1
    fi
fi

echo "Building sherlock..."
$GO_BIN build -o sherlock ./cmd/sherlock/
echo "Setup complete"
