#!/usr/bin/env bash
# Host-side dependency pre-staging (SAFETY: --ignore-scripts — no package
# lifecycle code executes; only npm's own trusted machinery runs, networked).
# Populates corpus/npm-cache with the dependency tree for one tarball, so the
# offline sandbox install resolves everything from cache and never needs DNS.
# Usage: ./scripts/prestage.sh <tarball>
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARBALL="${1:?usage: prestage.sh <tarball>}"
case "$TARBALL" in /*) SRC="$TARBALL" ;; *) SRC="$ROOT/$TARBALL" ;; esac
[ -f "$SRC" ] || { echo "[catchgate] tarball not found: $SRC"; exit 1; }
mkdir -p "$ROOT/corpus/npm-cache"
docker run --rm \
  -v "$ROOT/corpus/npm-cache:/npmcache" \
  -v "$SRC:/pkg.tgz:ro" \
  node:20-slim \
  bash -c "mkdir -p /project && cd /project && npm init -y >/dev/null 2>&1 && npm install --ignore-scripts --no-audit --no-fund --cache /npmcache /pkg.tgz" \
  && echo "[catchgate] cache primed: $(basename "$TARBALL")"
