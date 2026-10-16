#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

read -r -p "Удалить ВСЕ данные платформы (пользователи, решения, рейтинг)? Введите yes: " ANSWER
if [ "$ANSWER" != "yes" ]; then
  echo "Отменено"
  exit 0
fi

docker compose down -v
docker compose up -d
echo "Данные удалены, платформа запущена с пустой базой"
