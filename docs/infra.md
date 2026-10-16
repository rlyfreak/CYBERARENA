# Инфраструктура CYBERARENA

Платформа работает в Docker и открывается на http://localhost:8080
Все команды выполняются из корня репозитория. 

## 1. Перед первым запуском

Пароль администратора по ТЗ не хранится в репозитории, его нужно задать локально. Без него проект не запустится.

Скопировать файл `.env.example` в `.env` (в той же папке), открыть `.env` и вместо `change-me` вписать любой пароль. Файл `.env` в Git не попадает.

В коде логин и пароль читаются так:
`os.getenv("ADMIN_USERNAME")` и `os.getenv("ADMIN_PASSWORD")`

## 2. Сборка и запуск

```
docker compose up -d --build
docker compose ps
```

Через 10–20 секунд у всех трёх сервисов должен появиться статус `(healthy)`.

| Адрес | Что там |
|-------|---------|
| http://localhost:8080/ | Главная страница |
| http://localhost:8080/docs | Swagger |
| http://localhost:8080/api/health | Проверка бэкенда |
| http://localhost:8080/lab/ | Учебная лаборатория |

## 3. После изменений в коде

Код попадает в контейнер только при сборке. После любых изменений в `backend/` (в том числе в `requirements.txt`) выполнить:

```
docker compose up -d --build
```

Без `--build` запустится старая версия кода.

## 4. Перезапуск и остановка

| Задача | Команда |
|--------|---------|
| Перезапустить всё | `docker compose restart` |
| Перезапустить только бэкенд | `docker compose restart app` |
| Остановить (данные сохраняются) | `docker compose down` |
| Удалить все данные и начать с пустой базы | `docker compose down -v`, затем `docker compose up -d` |

`docker compose down -v` удаляет базу безвозвратно, использовать только для полного сброса.

## 5. Диагностика

| Задача | Команда |
|--------|---------|
| Состояние сервисов | `docker compose ps` |
| Логи бэкенда | `docker compose logs -f app` |
| Логи всех сервисов | `docker compose logs -f --tail=100` |
| Зайти в контейнер бэкенда | `docker compose exec app sh` |

Если сервис не `healthy` — посмотреть его логи, причина обычно там.

## 6. Частые проблемы

| Симптом | Что делать |
|---------|------------|
| `Задайте ADMIN_PASSWORD в файле .env` | Нет файла `.env`, см. пункт 1 |
| `address already in use` на 8080 | Порт занят другой программой, её нужно закрыть |
| Бэкенд не становится `healthy` | Посмотреть `docker compose logs app`, обычно там ошибка в коде |
| Изменения в коде не видны | Пересобрать с `--build`, см. пункт 3 |

## 7. Главная страница

Шаблон лежит в `frontend/templates/index.html`. Чтобы он открывался по адресу `/`, нужно добавить:

В `backend/requirements.txt`:

```
jinja2>=3.1,<4.0
```

В `backend/app/main.py`:

```python
import os
from pathlib import Path
from fastapi import Request
from fastapi.templating import Jinja2Templates

TEMPLATES_DIR = os.getenv(
    "TEMPLATES_DIR",
    str(Path(__file__).resolve().parents[2] / "frontend" / "templates"),
)
templates = Jinja2Templates(directory=TEMPLATES_DIR)

@app.get("/", include_in_schema=False)
async def index(request: Request):
    return templates.TemplateResponse(request, "index.html")
```

Затем выполнить `docker compose up -d --build`.
