# CYBERARENA
Self-hosted CTF platform for cybersecurity training. Developed by 404клуб for IT Sprint 2026 (School 21).

## Первый запуск

Нужны Docker с Compose и Python для генерации секрета. Все команды выполняются
из корня репозитория.

1. Скопируйте `.env.example` в `.env`:

   ```text
   cp .env.example .env
   ```

   В PowerShell используйте `Copy-Item .env.example .env`. Это действие нужно
   только при первом запуске: существующий `.env` не перезаписывайте.

2. Откройте `.env` в локальном редакторе и замените `ADMIN_PASSWORD` собственным
   паролем длиной **12–128 символов**. `ADMIN_USERNAME=admin` можно оставить.
3. Сгенерируйте случайный `SESSION_SECRET` и вставьте его в `.env`:

   ```text
   python -c "import secrets; print(secrets.token_urlsafe(48))"
   ```

   Секрет должен содержать **минимум 32 символа**. Результат команды — секрет:
   не публикуйте его и не отправляйте в логи CI, отчёты или переписку.
4. Соберите и запустите платформу:

   ```text
   docker compose up -d --build
   ```

5. Проверьте все контейнеры:

   ```text
   docker compose ps --all
   ```

   Дождитесь статуса `healthy` у `app`, `nginx`, `lab-gateway` и `lab-web`.
   Если контейнер завершился или нездоров, смотрите [диагностику](docs/infra.md).
6. Откройте [http://localhost:8080](http://localhost:8080).
   При первом входе администратора потребуется сменить начальный пароль.

**Значения `REPLACE_WITH_YOUR_PASSWORD` и `REPLACE_WITH_RANDOM_SECRET` —
публичные заглушки. Замените обе до запуска; они не подходят для рабочей установки.**
Настоящий `.env` игнорируется Git; `.env.example` остаётся отслеживаемым шаблоном.
Для существующей установки сохраняйте прежний `SESSION_SECRET` и `.env` при
обновлении: смена ключа подписи сделает текущие браузерные cookie недействительными.

**`docker compose down -v` удаляет том SQLite вместе с данными.** Для обычной
остановки используйте `docker compose down` без `-v`. Обновление приложения
не требует удаления тома или пересоздания базы.

## Документация

- [Инфраструктура](docs/infra.md)
- [CTF Core и управление заданиями](docs/ctf-core.md)
- [Проверки CTF Core](docs/ctf-verification.md)
