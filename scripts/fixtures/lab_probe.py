"""Test-only wrapper around the real WEB-01 handler; never in the lab image."""

import importlib.util
import json
from http.server import ThreadingHTTPServer
from urllib.parse import urlsplit

spec = importlib.util.spec_from_file_location('web01', '/lab/server.py')
assert spec is not None and spec.loader is not None
web01 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(web01)


class Handler(web01.Handler):
    def do_GET(self):
        if urlsplit(self.path).path == '/__isolation-probe__':
            body = json.dumps({'cookie': self.headers.get('Cookie', '')}).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Set-Cookie', 'lab_probe=untrusted; Path=/')
            self.end_headers()
            self.wfile.write(body)
            return
        super().do_GET()


if __name__ == '__main__':
    ThreadingHTTPServer(('0.0.0.0', 8000), Handler).serve_forever()
