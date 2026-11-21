#!/usr/bin/env bash
# CatchGate — batch-scan packages end-to-end: fetch -> sandbox install -> verdict.
# Usage: ./scripts/scan_benign.sh left-pad lodash chalk ms is-even
# (unscoped package names for now)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$ROOT/corpus/benign" "$ROOT/traces"

for PKG in "$@"; do
  echo "=== ${PKG} ==="
  # host-side fetch (networked helper container; benign packages from the npm registry)
  docker run --rm -v "$ROOT/corpus:/corpus" node:20-slim \
    npm pack "$PKG" --pack-destination /corpus/benign >/dev/null 2>&1 \
    || { echo "  FETCH FAILED"; continue; }
  TGZ=$(ls -t "$ROOT/corpus/benign/${PKG}"-*.tgz 2>/dev/null | head -1)
  [ -n "$TGZ" ] || { echo "  no tarball found"; continue; }
  if ! "$ROOT/scripts/run_install.sh" "corpus/benign/$(basename "$TGZ")" >/dev/null 2>&1; then
    echo "  (install failed or timed out - verdict on partial trace)"
  fi
  NAME=$(basename "$TGZ" .tgz)
  python3 "$ROOT/src/rules.py" "traces/${NAME}.trace" 2>/dev/null \
    | python3 -c 'import json,sys; v=json.load(sys.stdin); print(" ", v["verdict"], "|", ", ".join(r["rule"] for r in v["rules_fired"]) or "no rules fired")'
done
echo "=== batch done ==="
