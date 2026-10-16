#!/usr/bin/env bash
set -u
cd "$(dirname "$0")/.."

URL="http://localhost:8080"

section() { printf '\n== %s ==\n' "$1"; }
check() {
  local code
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$URL$1")
  if [ "$code" = "$2" ]; then
    echo "  OK    $1 -> $code"
  else
    echo "  FAIL  $1 -> $code (ожидали $2)"
  fi
}

section "Версии"
docker --version
docker compose version

section "Контейнеры"
docker compose ps

section "Адреса через nginx"
check /nginx-health 200
check /api/health 200
check /docs 200
check /lab/healthz 200

section "Порт"
docker compose port nginx 80

section "Память и CPU"
docker stats --no-stream --format 'table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}' $(docker compose ps -q)

section "База"
docker compose exec -T app ls -l /code/data

section "Ошибки в логах"
ERRS=$(docker compose logs --tail=200 2>&1 | grep -E '\[(error|emerg|crit)\]|Traceback|ERROR|Exception' | tail -n 20)
if [ -n "$ERRS" ]; then
  echo "$ERRS"
else
  echo "  ошибок не найдено"
fi
