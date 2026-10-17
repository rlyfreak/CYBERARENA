#!/usr/bin/env bash
set -u
cd "$(dirname "$0")/.."

FAILED=0
ok()   { echo "  OK    $1"; }
fail() { echo "  FAIL  $1"; FAILED=1; }
lab()  { docker compose exec -T lab-web "$@" >/dev/null 2>&1; }

if ! docker compose ps --status running -q lab-web | grep -q .; then
  echo "lab-web не запущен: docker compose up -d"
  exit 1
fi

echo "Проверка изоляции lab-web"

if lab python -c "import socket; socket.create_connection(('app', 8000), timeout=3)"; then
  fail "лаборатория видит бэкенд app:8000"
else
  ok "нет доступа к бэкенду"
fi

if lab python -c "import urllib.request; urllib.request.urlopen('http://nginx/api/health', timeout=3)"; then
  fail "лаборатория достигает приложения через внешний nginx"
else
  ok "нет обхода через внешний nginx"
fi

if lab python -c "import urllib.request; r=urllib.request.urlopen('http://lab-gateway:8000/api/health', timeout=3); assert r.status == 200"; then
  fail "lab-gateway проксирует API приложения"
else
  ok "lab-gateway обслуживает только лабораторию"
fi

if lab python -c "import socket; socket.create_connection(('1.1.1.1', 443), timeout=3)"; then
  fail "у лаборатории есть интернет"
else
  ok "нет выхода в интернет"
fi

if lab test -e /var/run/docker.sock; then
  fail "в лаборатории есть Docker Socket"
else
  ok "нет Docker Socket"
fi

if lab test -e /code/data; then
  fail "в лаборатории есть папка с базой"
else
  ok "нет доступа к базе"
fi

if lab touch /lab/hacked; then
  fail "файловая система доступна на запись"
else
  ok "файловая система только для чтения"
fi

if [ "$(docker compose exec -T lab-web id -u)" = "0" ]; then
  fail "процесс работает от root"
else
  ok "процесс работает не от root"
fi

CID=$(docker compose ps -q lab-web)
echo
docker inspect "$CID" --format '  ReadOnly={{.HostConfig.ReadonlyRootfs}} Privileged={{.HostConfig.Privileged}} CapDrop={{.HostConfig.CapDrop}} SecOpt={{.HostConfig.SecurityOpt}}'
docker inspect "$CID" --format '  Memory={{.HostConfig.Memory}} CPU={{.HostConfig.NanoCpus}} Mounts={{len .Mounts}} Tmpfs={{.HostConfig.Tmpfs}}'
echo

if [ "$FAILED" = 0 ]; then
  echo "ИТОГ: изоляция в порядке"
else
  echo "ИТОГ: есть проблемы"
  exit 1
fi
