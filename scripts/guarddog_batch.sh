#!/usr/bin/env bash
# Stage 7 baseline: GuardDog over every staged package dir.
# Usage: ./scripts/guarddog_batch.sh corpus/staging results/malicious_guarddog.csv
set -uo pipefail
export PATH="$HOME/.local/bin:$PATH"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIR="${1:?usage: guarddog_batch.sh <staging-dir> <out-csv>}"
OUT="${2:?usage: guarddog_batch.sh <staging-dir> <out-csv>}"
case "$OUT" in /*) OUTF="$OUT" ;; *) OUTF="$ROOT/$OUT" ;; esac
case "$DIR" in /*) DIRF="$DIR" ;; *) DIRF="$ROOT/$DIR" ;; esac
mkdir -p "$(dirname "$OUTF")"
echo "package,guarddog_flag,first_rule" > "$OUTF"
COUNT=0
for D in "$DIRF"/*/; do
  [ -d "$D" ] || continue
  COUNT=$((COUNT+1))
  NAME=$(basename "$D")
  OUT=$(guarddog npm scan "$D" 2>/dev/null)
  if echo "$OUT" | grep -qE "found [0-9]+ risks"; then
    N=$(echo "$OUT" | grep -oE "found [0-9]+ risks" | grep -oE "[0-9]+" | head -1)
    RULE=$(echo "$OUT" | grep -oE "threat\.[a-z..]+" | head -1)
    echo "$NAME,$N,${RULE:-unspecified}" >> "$OUTF"
    echo "  $NAME: FLAG ($N risks, $RULE)"
  else
    echo "$NAME,0," >> "$OUTF"
    echo "  $NAME: clean"
  fi
done
echo "--- GuardDog baseline complete: $COUNT packages -> $OUTF ---"
