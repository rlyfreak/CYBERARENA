#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

FILE="${1:-}"
if [ -z "$FILE" ] || [ ! -f "$FILE" ]; then
  echo "Использование: ./scripts/restore-db.sh backups/<файл>.db"
  exit 1
fi

docker compose stop app
docker compose run --rm --no-deps -T --entrypoint sh app -c 'cat > /code/data/cyberarena.db' < "$FILE"
docker compose start app
echo "База восстановлена из $FILE"
