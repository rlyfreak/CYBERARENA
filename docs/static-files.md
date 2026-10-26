# Публичные материалы заданий

nginx раздаёт `/files/` из каталога `files/`, подключённого только к nginx
в режиме чтения. Backend и лаборатория этот каталог не получают. Новых портов
и сетевых соединений между сервисами нет.

## Размещение настоящих материалов

- WEB-02: `files/web-02/index.html`, при необходимости соседние JS/CSS.
  Ссылка в карточке: `/files/web-02/`.
- CRYPTO-01: `files/crypto-01/challenge.txt`.
  Ссылка в карточке: `/files/crypto-01/challenge.txt`.
- В `files/crypto-01/` уже находится настоящий материал CRYPTO-01.
  Настоящий WEB-02 добавляется отдельно; инфраструктурный fixture не является заданием.
  Все размещённые здесь файлы публичны, независимо от публикации карточки.
  Не размещайте .env, пароли платформы, авторские write-up, базы или резервные копии.
- Список файлов отключён; неизвестный файл получает 404; скрытые файлы
  не раздаются; символьные ссылки запрещены.
- HTML получает CSP `sandbox allow-scripts`: JS может работать, но документ
  не получает origin платформы, доступ к её DOM, cookie и API с её сессией.
  Код задания не должен требовать origin платформы. Открытие в новой вкладке
  и скачивание текстового файла нужно отдельно проверить в браузере.

После изменения конфигурации:
`docker compose up -d --force-recreate nginx`.
После изменения только содержимого файлов пересборка образа не нужна.

## Проверка инфраструктуры

`compose.ctf-test.yaml` подключает отдельный каталог
`scripts/fixtures/files/` через отдельный read-only тестовый том вместо настоящих материалов.
Setup-контейнер копирует fixtures в этот том и добавляет контрольный симлинк;
nginx не может менять том. Это явные проверочные
файлы без флагов, не готовые WEB-02/CRYPTO-01.

CI выполняет `nginx -t`, проверку рабочего Compose без вывода секретов и:

```text
python scripts/check_static_files.py --base http://127.0.0.1:18080 --root scripts/fixtures/files
```

Проверяются байты каждого файла (включая JS), HTML Content-Type,
индекс каталога, CSP/nosniff, 404 отсутствующего и скрытого файла,
403 вместо листинга. Перенаправление на другую страницу не считается успехом.
Проверка завершается ошибкой при пустом каталоге или расхождении содержимого.

После появления настоящих материалов выполните ту же проверку с
`--base http://127.0.0.1:8080 --root files`, затем проверьте карточки через
frontend и скачивание в браузере. Одни fixtures не закрывают К-2 аудита:
нужны условия, реальные материалы, настроенные флаги и write-up обоих заданий.
Не публикуйте черновики как готовые задания.

## Публикация и откат на рабочем стенде

Материалы попадают в `files/` только через `main` (PR с проверкой CI).
`files/` подключён к nginx как каталог хоста: он не входит в образы и volume
базы, поэтому `docker compose up -d --build`, `--force-recreate` и
`docker compose down` его не удаляют. `scripts/reset-data.sh` удаляет только
базу.

Команды ниже — для Linux/WSL, Bash, из корня доверенного checkout. Выполняйте
публикацию одним оператором: параллельное изменение checkout запрещено.
Этот порядок обновляет только материалы. Если между версиями меняются backend,
frontend, лаборатория, nginx или Compose, сначала нужен отдельный согласованный
деплой приложения; приведённая команда остановится до остановки nginx.

Проверка привязывает локальные байты к конкретному Git-коммиту, запрещает
неотслеживаемые (включая игнорируемые) файлы, симлинки, скрытые файлы кроме
`.gitkeep`, неверные права и владельца. Запускается **до** открытия HTTP-доступа.
Не запускайте процедуру через sudo и не исправляйте владельца рекурсивно без
проверки путей.

В одной Bash-сессии определите проверку:

```bash
set -Eeuo pipefail
check_materials() {
    local expected="$1" bad
    test -d files && test ! -L files
    git diff --quiet "$expected" -- files/
    bad=$(git ls-files --others -- files/)
    test -z "$bad" || { echo 'ERROR: untracked material files' >&2; return 1; }
    bad=$(find files -type l -print -quit)
    test -z "$bad" || { echo 'ERROR: symlink in files/' >&2; return 1; }
    bad=$(find files -name '.*' ! -name .gitkeep -print -quit)
    test -z "$bad" || { echo 'ERROR: hidden material' >&2; return 1; }
    bad=$(find files -type f ! -perm -o=r -print -quit)
    test -z "$bad" || { echo 'ERROR: unreadable material' >&2; return 1; }
    bad=$(find files -type d ! -perm -o=rx -print -quit)
    test -z "$bad" || { echo 'ERROR: inaccessible material directory' >&2; return 1; }
    bad=$(find files ! -uid "$(id -u)" -print -quit)
    test -z "$bad" || { echo 'ERROR: unexpected material owner' >&2; return 1; }
}
```

Публикация в той же сессии:

```bash
git fetch origin main
test -z "$(git status --porcelain --untracked-files=all)"
previous=$(git rev-parse HEAD)
target=$(git rev-parse 'origin/main^{commit}')
git merge-base --is-ancestor "$previous" "$target"
git diff --quiet "$previous" "$target" -- backend/ frontend/ labs/ nginx/ compose.yaml
printf '%s\n' "$previous" > ../cyberarena-files.prev
# После остановки любая ошибка оставляет nginx остановленным, включая ошибку HTTP-проверки.
trap 'failure=$?; if docker compose stop nginx; then echo "ERROR: publication failed; nginx stopped" >&2; else echo "CRITICAL: cannot stop nginx; block HTTP access manually" >&2; fi; exit "$failure"' ERR
docker compose stop nginx
git merge --ff-only "$target"
check_materials "$target"
docker compose up -d --wait nginx
python scripts/check_static_files.py --base http://127.0.0.1:8080 --root files
check_materials "$target"
printf 'Published Git SHA: %s\n' "$target"
git ls-files -z files/ | xargs -0 sha256sum
trap - ERR
```

Ошибка до остановки nginx не меняет работающий стенд. Ошибка после остановки
оставляет его недоступным до осознанного отката при успешной работе Docker.
Если Docker не смог остановить nginx, выводится CRITICAL: оператор должен
немедленно закрыть HTTP-доступ средствами хоста; продолжать публикацию нельзя.
После ошибки не продолжайте блок со следующей строки. `check_static_files.py`
сравнивает HTTP с **локальными файлами**, а `check_materials` отдельно сверяет
их с выбранным коммитом и проверяет допустимый состав каталога. Сохраните Git
SHA и контрольные суммы в отчёте. Карточки публикуйте только после успеха.

Откат материалов: в новой Bash-сессии сначала повторите определение
`check_materials` выше, затем выполните блок. Сохранённый SHA должен относиться
к тому же репозиторию и предыдущему согласованному состоянию.

```bash
previous=$(git rev-parse --verify "$(cat ../cyberarena-files.prev)^{commit}")
trap 'failure=$?; if docker compose stop nginx; then echo "ERROR: rollback failed; nginx stopped" >&2; else echo "CRITICAL: cannot stop nginx; block HTTP access manually" >&2; fi; exit "$failure"' ERR
docker compose stop nginx
git restore --source="$previous" --worktree -- files/
check_materials "$previous"
docker compose up -d --wait nginx
python scripts/check_static_files.py --base http://127.0.0.1:8080 --root files
check_materials "$previous"
printf 'Rolled back materials to Git SHA: %s\n' "$previous"
trap - ERR
```

Откат не меняет HEAD, базу или образы приложения: рабочие материалы намеренно
отличаются от HEAD. Убедитесь, что карточки совместимы с возвращённой версией.
Для возврата к текущему HEAD в той же сессии: остановите nginx, выполните
`git restore --source=HEAD --worktree -- files/`, `check_materials HEAD`, затем
запуск nginx и обе проверки, как выше; сохраните trap до завершения.

## Проверка изоляции лаборатории

`python scripts/ctf_smoke.py lab-isolation` проверяет контрольный прямой запрос
к test-only upstream, обычный маршрут gateway и внешний proxy независимо.
Пробник `scripts/fixtures/lab_probe.py` оборачивает настоящий WEB-01 только в
`compose.ctf-test.yaml`: production-образ и production Compose его не включают.
Существующий отдельный virtual host оставлен для внешнего proxy и 502/503/504.

После `ctf_smoke.py prepare` запускается `python scripts/check_lab_browser.py`.
Он входит тестовым участником, подтверждает доступ платформы к защищённому API,
затем проверяет запрет чтения cookie и DOM между платформой и лабораторией,
недоступность API из JS лаборатории и ответ 401 без платформенной сессии.
Переходы к документам WEB-01 и обратно продолжают работать. Этот тест не
подменяет настоящее WEB-02 и не объявляет его готовым.
