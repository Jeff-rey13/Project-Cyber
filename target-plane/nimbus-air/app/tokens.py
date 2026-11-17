"""Minimal signed bearer tokens: base64url(json payload) + "." + hmac-sha256.

Not a JWT on purpose. It's small enough to audit in one read, which matters
because the broken-auth weakness lives right here.
"""

import base64
import hashlib
import hmac
import json
import time


class TokenError(Exception):
    pass


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _sign(body: str, secret: str) -> str:
    return hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()


def issue(subject: int, secret: str, ttl_seconds: int, now: float | None = None) -> str:
    now = time.time() if now is None else now
    body = _b64(json.dumps({"sub": subject, "exp": int(now) + ttl_seconds}, separators=(",", ":")).encode())
    return f"{body}.{_sign(body, secret)}"


def decode(token: str, secret: str, verify_signature: bool = True, now: float | None = None) -> dict:
    now = time.time() if now is None else now
    try:
        body, sig = token.split(".", 1)
        payload = json.loads(_unb64(body))
    except (ValueError, json.JSONDecodeError) as exc:
        raise TokenError("malformed token") from exc

    if verify_signature and not hmac.compare_digest(sig, _sign(body, secret)):
        raise TokenError("bad signature")
    if not isinstance(payload, dict) or not isinstance(payload.get("sub"), int):
        raise TokenError("bad payload")
    if verify_signature and payload.get("exp", 0) < now:
        raise TokenError("expired")
    return payload
