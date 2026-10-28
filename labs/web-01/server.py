import os
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

def valid_flag(flag):
    return (
        isinstance(flag, str)
        and 6 <= len(flag) <= 256
        and flag.startswith("CTF{")
        and flag.endswith("}")
        and all(33 <= ord(char) <= 126 and char not in "{}" for char in flag[4:-1])
    )


DOCUMENTS = {
    "101": {
        "title": "Правила работы с архивом",
        "content": "Все документы имеют уникальные номера. "
        "Некоторые записи доступны только сотрудникам.",
        "private": False,
    },
    "102": {
        "title": "Журнал изменений",
        "content": "Запись от 12.10.2026: документ №103 перенесён "
        "в закрытый раздел. Доступ разрешён администраторам.",
        "private": False,
    },
    "103": {
        "title": "Служебный документ",
        "content": "Конфиденциальная запись внутреннего архива.",
        "private": True,
    },
}


def render_page(title, content):
    return f"""<!doctype html>
<html lang="ru">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{escape(title)} | ARCHIVE</title>
    <style>
        body {{
            background: #101318;
            color: #e8edf2;
            font: 16px/1.6 system-ui, sans-serif;
            max-width: 850px;
            margin: 60px auto;
            padding: 0 20px;
        }}
        header {{
            border-bottom: 1px solid #39414d;
            padding-bottom: 16px;
            margin-bottom: 35px;
        }}
        .muted {{ color: #a0acba; }}
        .card {{
            background: #1c222b;
            border: 1px solid #39414d;
            padding: 22px;
            border-radius: 8px;
            margin: 15px 0;
        }}
        a {{ color: #80e0c1; }}
        code {{
            background: #293341;
            padding: 4px 8px;
            border-radius: 4px;
        }}
    </style>
</head>
<body>
<header>
    <strong>INTERNAL ARCHIVE / 2026</strong>
    <div class="muted">Система хранения внутренних документов</div>
</header>
<main>
    <h1>{escape(title)}</h1>
    {content}
</main>
</body>
</html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "archive"
    sys_version = ""

    def send_page(self, status, content, content_type="text/html; charset=utf-8"):
        data = content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        request = urlsplit(self.path)
        path = request.path

        if path == "/healthz":
            return self.send_page(200, '{"status":"ok"}', "application/json")

        if path == "/status":
            return self.send_page(
                200, render_page("Статус системы", "<p>Архив работает.</p>")
            )

        if path == "/":
            cards = ""

            for doc_id, doc in DOCUMENTS.items():
                if doc["private"]:
                    continue

                cards += f"""
                <div class="card">
                    <div class="muted">DOCUMENT #{doc_id}</div>
                    <h2>{escape(doc["title"])}</h2>
                    <a href="document?id={doc_id}">Открыть документ →</a>
                </div>
                """

            return self.send_page(
                200,
                render_page(
                    "Реестр документов",
                    "<p>Вы вошли в архив как гость. "
                    "Отображаются только общедоступные записи.</p>" + cards,
                ),
            )

        if path == "/document":
            query = parse_qs(request.query)
            doc_id = query.get("id", [""])[0]
            doc = DOCUMENTS.get(doc_id)

            if doc is None:
                return self.send_page(
                    404,
                    render_page(
                        "Документ не найден",
                        "<p>Запись с таким номером отсутствует.</p>",
                    ),
                )

            content = f"""
                <p class="muted">DOCUMENT #{escape(doc_id)}</p>
                <div class="card">
                    <p>{escape(doc["content"])}</p>
                </div>
            """

            if doc["private"]:
                flag = os.environ.get("WEB01_FLAG")
                content += (
                    f"<p><code>{escape(flag)}</code></p>"
                    if flag
                    else "<p>Флаг лаборатории пока не настроен.</p>"
                )

            content += '<p><a href="./">← Вернуться в архив</a></p>'

            # УЧЕБНАЯ УЯЗВИМОСТЬ:
            # Сервер проверяет существование документа,
            # но не проверяет права пользователя на его просмотр.
            return self.send_page(200, render_page(doc["title"], content))

        return self.send_page(404, render_page("404", "<p>Страница не найдена.</p>"))


if __name__ == "__main__":
    if not valid_flag(os.environ.get("WEB01_FLAG")):
        raise SystemExit("WEB01_FLAG must have format CTF{...}, 6-256 printable ASCII characters")
    ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
