#!/usr/bin/env bash
# CatchGate Stage 3 — plant FAKE canary credentials inside the sandbox home.
# Every value below is deliberately fake. NEVER put a real credential here.
set -euo pipefail
HOME_DIR="${1:?usage: plant_canaries.sh <home-dir>}"

mkdir -p "$HOME_DIR/.ssh" "$HOME_DIR/.aws"
# fake npm auth token (clearly fake prefix per canary convention)
echo "//registry.npmjs.org/:_authToken=FAKECADE2CANARYTOKEN000000000000000000000000" > "$HOME_DIR/.npmrc"
# fake deploy key
echo "FAKE-CADE-CANARY-PRIVATE-KEY-DO-NOT-USE" > "$HOME_DIR/.ssh/id_rsa"
# fake cloud creds
printf '[default]\naws_access_key_id=AKIACADEMIA000000\naws_secret_access_key=FAKECADE2CANARYSECRET0000000000000000000000000000\n' > "$HOME_DIR/.aws/credentials"
# fake app env with a bait secret
printf 'APP_ENV=production\nDATABASE_URL=postgres://admin:FAKECADE2CANARYPW@db.internal:5432/app\n' > "$HOME_DIR/.env"
echo "[catchgate] canaries planted in $HOME_DIR"
