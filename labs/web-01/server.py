from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PAGE = """<!doctype html><html lang="ru"><head><meta charset="utf-8">
<title>WEB-01</title></head><body>
<h1>Учебная лаборатория WEB-01</h1>
<p>Заглушка.</p>
<p><a href="status">Проверить относительную ссылку</a></p>
<p><a href="/">Назад на платформу</a></p>
</body></html>"""

class Handler(BaseHTTPRequestHandler):
    server_version = "lab"
    sys_version = ""

    def _send(self, code, body, ctype="text/html; charset=utf-8"):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/healthz":
            self._send(200, '{"status":"ok"}', "application/json")
        elif path == "/":
            self._send(200, PAGE)
        elif path == "/status":
            self._send(200, "<p>Префикс /lab/ срезается правильно.</p><a href='./'>Назад</a>")
        else:
            self._send(404, "<p>Not found</p>")

if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
