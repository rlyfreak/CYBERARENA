#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p backups
OUT="backups/cyberarena-$(date +%Y%m%d-%H%M%S).db"

docker compose exec -T app python -c "
import sqlite3
src = sqlite3.connect('/code/data/cyberarena.db')
dst = sqlite3.connect('/tmp/backup.db')
src.backup(dst)
dst.close()
src.close()
"
docker compose exec -T app cat /tmp/backup.db > "$OUT"
docker compose exec -T app rm -f /tmp/backup.db

echo "Резервная копия: $OUT ($(du -h "$OUT" | cut -f1))"
