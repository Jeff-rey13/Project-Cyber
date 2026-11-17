"""Forward http proxy that pushes external engines (zap, nuclei) through the scope gate.

External tools send their own traffic, so we can't hand them our python
client. Instead they get this proxy as their only upstream, and their
container gets no other route out (see docker-compose). Every proxied
request is replayed through the guarded client, so it's the same gate,
same stats, same audit trail as the in-process engines.

Plain http only. CONNECT is refused: we'd need to mitm tls to see the path,
and the bundled lab is http anyway. https targets are a known gap for the
external engines; in-process engines handle https fine.
"""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx

from .guarded_client import ScopeViolation

# hop-by-hop headers (rfc 9110 7.6.1) plus proxy credentials, never forwarded
_DROP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "proxy-connection",
         "te", "trailer", "transfer-encoding", "upgrade", "host", "content-length", "accept-encoding"}
MAX_BODY = 5 * 1024 * 1024


def _handler_for(client: httpx.Client):
    class GateProxyHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):  # quiet; the gate stats/audit are the real log
            pass

        def _reply(self, code: int, body: bytes, headers: dict | None = None):
            self.send_response(code)
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _forward(self):
            url = self.path
            if not url.lower().startswith("http://"):
                return self._reply(400, b"aeroscan gate proxy: absolute http:// url required")
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY:
                return self._reply(413, b"aeroscan gate proxy: body too large")
            body = self.rfile.read(length) if length else None
            headers = {k: v for k, v in self.headers.items() if k.lower() not in _DROP}
            try:
                r = client.request(self.command, url, headers=headers, content=body)
            except ScopeViolation as exc:
                return self._reply(403, f"aeroscan gate: {exc.decision.reason}".encode(), {"X-AeroScan-Gate": "deny"})
            except httpx.HTTPError as exc:
                return self._reply(502, f"aeroscan gate proxy: upstream error {type(exc).__name__}".encode())
            out = {k: v for k, v in r.headers.items() if k.lower() not in _DROP | {"content-encoding"}}
            self._reply(r.status_code, r.content, out)

        def do_CONNECT(self):
            self._reply(403, b"aeroscan gate proxy: CONNECT not supported", {"X-AeroScan-Gate": "deny"})

        do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = do_TRACE = _forward

    return GateProxyHandler


class GateProxy:
    def __init__(self, client: httpx.Client, host: str = "127.0.0.1", port: int = 0):
        self._server = ThreadingHTTPServer((host, port), _handler_for(client))
        self._server.daemon_threads = True
        self._thread: threading.Thread | None = None

    @property
    def address(self) -> tuple[str, int]:
        host, port = self._server.server_address[:2]
        return str(host), int(port)

    def __enter__(self) -> "GateProxy":
        self._thread = threading.Thread(target=self._server.serve_forever, name="aeroscan-gate-proxy", daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._server.shutdown()
        self._server.server_close()
