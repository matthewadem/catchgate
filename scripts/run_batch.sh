#!/usr/bin/env bash
# Stage 6 batch runner: full pipeline over every tarball in a corpus dir.
# Usage: ./scripts/run_batch.sh corpus/malicious results/malicious_catchgate.csv
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIR="${1:?usage: run_batch.sh <corpus-dir> <out-csv>}"
OUT="${2:?usage: run_batch.sh <corpus-dir> <out-csv>}"
mkdir -p "$(dirname "$OUT")"
echo "package,verdict,rules" > "$OUT"
COUNT=0
case "$DIR" in /*) FULL="$DIR" ;; *) FULL="$ROOT/$DIR" ;; esac
for TGZ in "$FULL"/*.tgz; do
  [ -e "$TGZ" ] || continue
  COUNT=$((COUNT+1))
  NAME=$(basename "$TGZ" .tgz)
  if ! "$ROOT/scripts/run_install.sh" "$FULL/$(basename "$TGZ")" >/dev/null 2>&1; then
    : # timeout/failure is fine - verdict runs on the partial trace
  fi
  case "$OUT" in /*) OUTFULL="$OUT" ;; *) OUTFULL="$ROOT/$OUT" ;; esac
[ -f "traces/${NAME}.trace" ] && python3 "$ROOT/src/scan_one.py" "$NAME" "traces/${NAME}.trace" "$OUTFULL" \
    || echo "$NAME,NO_TRACE," >> "$OUTFULL"
done
echo "--- $COUNT packages scanned; results in $OUT ---"
