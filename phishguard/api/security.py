"""API hardening: rate limiting, request-size limits, auth, security headers."""

from __future__ import annotations

import hmac
import threading
import time
from collections import OrderedDict

from fastapi import HTTPException, Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send


class TokenBucketLimiter:
    """In-process token bucket per client.

    Limitation: per-replica state. Behind multiple replicas, use a shared
    store (Redis) or enforce limits at the gateway (nginx/Envoy/API GW).
    """

    def __init__(self, rate_per_minute: int, burst: int, max_clients: int = 50_000) -> None:
        self.rate = rate_per_minute / 60.0
        self.burst = float(burst)
        self.max_clients = max_clients
        self._buckets: OrderedDict[str, tuple[float, float]] = OrderedDict()
        self._lock = threading.Lock()

    def allow(self, key: str) -> tuple[bool, float]:
        now = time.monotonic()
        with self._lock:
            tokens, last = self._buckets.pop(key, (self.burst, now))
            tokens = min(self.burst, tokens + (now - last) * self.rate)
            allowed = tokens >= 1.0
            if allowed:
                tokens -= 1.0
            self._buckets[key] = (tokens, now)
            while len(self._buckets) > self.max_clients:
                self._buckets.popitem(last=False)
        retry_after = 0.0 if allowed else (1.0 - tokens) / self.rate
        return allowed, retry_after


def client_key(request: Request, trust_proxy: bool) -> str:
    api_key = request.headers.get("x-api-key")
    if api_key:
        return "key:" + api_key[:12]
    if trust_proxy:
        fwd = request.headers.get("x-forwarded-for", "")
        if fwd:
            return "ip:" + fwd.split(",")[0].strip()
    return "ip:" + (request.client.host if request.client else "unknown")


def check_api_key(request: Request, valid_keys: set[str]) -> None:
    if not valid_keys:
        return  # auth disabled (dev). Production compose sets PG_API_KEYS.
    supplied = request.headers.get("x-api-key", "")
    if not any(hmac.compare_digest(supplied, k) for k in valid_keys):
        raise HTTPException(status_code=401, detail="invalid or missing API key")


class BodySizeLimitMiddleware:
    """Reject oversized bodies *while streaming*, not after buffering them."""

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app, self.max_bytes = app, max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = dict(scope.get("headers") or [])
        cl = headers.get(b"content-length")
        if cl is not None and cl.isdigit() and int(cl) > self.max_bytes:
            await _send_413(send)
            return
        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            msg = await receive()
            if msg["type"] == "http.request":
                received += len(msg.get("body", b""))
                if received > self.max_bytes:
                    raise _TooLarge()
            return msg

        try:
            await self.app(scope, limited_receive, send)
        except _TooLarge:
            await _send_413(send)


class _TooLarge(Exception):
    pass


async def _send_413(send: Send) -> None:
    body = b'{"detail":"request body too large"}'
    await send({"type": "http.response.start", "status": 413,
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
    await send({"type": "http.response.body", "body": body})


SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    # JSON API: nothing should ever be rendered/executed from our responses.
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
}

# The built-in web UI needs its own same-origin script/style, but nothing else:
# no inline script, no third-party origins, no framing, no form posts.
UI_CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; "
          "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
