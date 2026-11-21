#!/usr/bin/env bash
# CatchGate Stage 3 — full sandboxed install: canaries -> strace -> offline install.
# Usage: ./scripts/run_install.sh <path-to-tarball>
#   ./scripts/run_install.sh corpus/benign/left-pad-1.3.0.tgz
set -euo pipefail

TARBALL="${1:?usage: run_install.sh <path-to-tarball>}"
[ -f "$TARBALL" ] || { echo "[catchgate] tarball not found: $TARBALL"; exit 1; }

# trace name from the tarball filename: left-pad-1.3.0.tgz -> left-pad-1.3.0.trace
NAME="$(basename "$TARBALL" .tgz)"
mkdir -p traces

# repo root, so the script works no matter where you call it from
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
case "$TARBALL" in /*) SRC="$TARBALL" ;; *) SRC="$ROOT/$TARBALL" ;; esac

echo "[catchgate] building sandbox image..."
docker build -t catchgate-sandbox "$ROOT/docker" >/dev/null

CACHE_MOUNT=""
CACHE_FLAGS=""
if [ -d "$ROOT/corpus/npm-cache" ]; then
  CACHE_MOUNT="-v $ROOT/corpus/npm-cache:/npmcache"
  CACHE_FLAGS="--offline --cache /npmcache"
fi

echo "[catchgate] installing ${TARBALL} -> traces/${NAME}.trace ..."
docker run --rm --network none \
  -v "$ROOT/traces:/traces" \
  -v "$SRC:/pkg.tgz:ro" \
  -v "$ROOT/scripts/plant_canaries.sh:/home/devuser/plant.sh:ro" \
  $CACHE_MOUNT \
  catchgate-sandbox \
  bash -c "bash ~/plant.sh \$HOME && cd ~/project && timeout 90 strace -f -o /traces/${NAME}.trace npm install --no-audit --no-fund $CACHE_FLAGS /pkg.tgz"

echo "[catchgate] done -> traces/${NAME}.trace"