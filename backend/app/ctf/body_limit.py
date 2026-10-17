import re

from starlette.responses import JSONResponse


class CtfBodyLimit:
    """Bound streamed bodies before parsing, including requests without Content-Length."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        path = scope.get('path', '')
        flag_request = re.fullmatch(r'/(?:api/challenges/\d+/submissions|challenges/\d+)', path)
        admin_request = path.startswith(('/api/admin/', '/admin/'))
        if scope['type'] != 'http' or scope['method'] not in ('POST', 'PATCH') or not (flag_request or admin_request):
            await self.app(scope, receive, send)
            return
        limit = 4096 if flag_request else 256 * 1024
        body = bytearray()
        while True:
            message = await receive()
            if message['type'] == 'http.disconnect':
                return
            body.extend(message.get('body', b''))
            if len(body) > limit:
                response = JSONResponse({'detail': 'Request body too large'}, status_code=413,
                                        headers={'Cache-Control': 'no-store'})
                await response(scope, receive, send)
                return
            if not message.get('more_body', False):
                break
        delivered = False

        async def replay():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {'type': 'http.request', 'body': bytes(body), 'more_body': False}
            return await receive()

        await self.app(scope, replay, send)
