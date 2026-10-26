#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p backups
OUT="backups/cyberarena-$(date +%Y%m%d-%H%M%S).db"
OUT_TMP="$OUT.tmp"
trap 'rm -f "$OUT_TMP"' EXIT

# Git Bash otherwise rewrites container paths such as /tmp to Windows paths.
MSYS_NO_PATHCONV=1 docker compose exec -T app python -c "
import sqlite3
src = sqlite3.connect('/code/data/cyberarena.db')
dst = sqlite3.connect('/tmp/backup.db')
src.backup(dst)
dst.close()
src.close()
"
MSYS_NO_PATHCONV=1 docker compose exec -T app cat /tmp/backup.db > "$OUT_TMP"
test -s "$OUT_TMP"
mv "$OUT_TMP" "$OUT"
MSYS_NO_PATHCONV=1 docker compose exec -T app rm -f /tmp/backup.db

echo "Резервная копия: $OUT ($(du -h "$OUT" | cut -f1))"
