"""Fixed errors for failures before application middleware runs."""

from aiohttp import web
from aiohttp.web_protocol import RequestHandler


class SafeRequestHandler(RequestHandler):
    def handle_error(self, request, status=500, exc=None, message=None):
        if request.writer.output_size:
            raise ConnectionError("the response has already started")
        response = web.Response(status=status, content_type="application/json",
            body=b'{"error":{"code":"invalid_request","message":"Request failed."}}',
            headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})
        response.force_close()
        return response


class SafeServer(web.Server):
    def __call__(self):
        return SafeRequestHandler(self, loop=self._loop, **self._kwargs)


class AppRunner(web.AppRunner):
    async def _make_server(self):
        # aiohttp has no public protocol factory argument. Keep this adapter
        # confined to the pinned aiohttp version and test actual parser errors.
        server = await super()._make_server()
        server._kwargs["auto_decompress"] = False
        return SafeServer(server.request_handler, request_factory=server.request_factory,
            handler_cancellation=server.handler_cancellation, loop=server._loop, **server._kwargs)
