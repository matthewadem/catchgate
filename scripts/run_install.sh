#!/usr/bin/env bash
# CatchGate Stage 1 — install one package inside the sandbox container.
# Usage: ./scripts/run_install.sh <package-name>
#
# Stage 2 will wrap this in strace. Stage 3 will plant canaries first.
set -euo pipefail

PACKAGE="${1:?usage: run_install.sh <package-name>}"

echo "[catchgate] building sandbox image..."
docker build -t catchgate-sandbox ../docker 2>/dev/null || docker build -t catchgate-sandbox "$(dirname "$0")/../docker"

echo "[catchgate] installing '${PACKAGE}' inside sandbox..."
docker run --rm --network none catchgate-sandbox npm install "$PACKAGE"

echo "[catchgate] done"
