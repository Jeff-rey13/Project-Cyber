"""authorize_request(): the single default-deny decision for every outbound request (PRD 5.1).

Shape of the function: a list of checks, each of which can only ever return
DENY. ALLOW is the last line and is reachable only if nothing objected.
Any exception while deciding is itself a DENY.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional
from urllib.parse import unquote, urlsplit

from .domains import InvalidDomain, canonical_domain
from .models import utcnow
from .snapshot import KNOWN_METHODS, ScopeSnapshot

ALLOWED_SCHEMES = {"http": 80, "https": 443}
# control chars, space, backslash: none of these belong in a url we'd send
_BAD_URL_CHARS = set(chr(c) for c in range(0x00, 0x21)) | {"\x7f", "\\"}


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    host: Optional[str] = None
    path: Optional[str] = None

    def __bool__(self) -> bool:
        return self.allowed


def DENY(reason: str, host: Optional[str] = None, path: Optional[str] = None) -> Decision:
    return Decision(False, reason, host, path)


@dataclass(frozen=True)
class Target:
    scheme: str
    host: str
    port: int
    path: str


def _fully_decoded(path: str) -> str:
    # decode until stable so %252e%252e can't survive as "%2e%2e" and slip past the dot-segment check
    prev = None
    for _ in range(5):
        if path == prev:
            return path
        prev, path = path, unquote(path, errors="strict")
    if path != prev:
        raise ValueError("too many encoding layers")
    return path


def parse_target(url: str) -> Target:
    """Strictly parse a url into canonical (scheme, host, port, decoded path). Raises ValueError."""
    if not isinstance(url, str) or not url or any(c in _BAD_URL_CHARS for c in url):
        raise ValueError("empty url or illegal characters")
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise ValueError("scheme not allowed")
    netloc = parts.netloc
    if not netloc or "@" in netloc:
        # userinfo is never legitimate for us and is the classic host-confusion trick
        raise ValueError("missing host or userinfo present")

    if netloc.startswith("["):
        end = netloc.find("]")
        if end == -1:
            raise ValueError("unterminated ipv6 literal")
        raw_host, rest = netloc[: end + 1], netloc[end + 1:]
    else:
        raw_host, sep, port_text = netloc.partition(":")
        rest = f":{port_text}" if sep else ""

    if rest:
        if not rest.startswith(":") or not rest[1:].isdigit() or not rest[1:].isascii():
            raise ValueError("bad port")
        port = int(rest[1:])
        if not 1 <= port <= 65535:
            raise ValueError("port out of range")
    else:
        port = ALLOWED_SCHEMES[scheme]

    host = canonical_domain(raw_host)
    path = _fully_decoded(parts.path or "/")
    if not path.startswith("/"):
        raise ValueError("relative path")
    # checked again post-decode: %5c becomes "\" and plenty of servers treat that as "/"
    if any(c in _BAD_URL_CHARS - {" "} for c in path):
        raise ValueError("control char or backslash in decoded path")
    segments = path.split("/")
    if any(seg in {".", ".."} for seg in segments):
        raise ValueError("dot segment in path")
    return Target(scheme, host, port, path)


def _under(path: str, prefix: str) -> bool:
    """Segment-aware prefix match: /bookings covers /bookings/X but not /bookingsadmin."""
    if prefix == "/":
        return True
    p = prefix.rstrip("/")
    return path == p or path.startswith(p + "/")


def authorize_request(
    method: str,
    url: str,
    snapshot: ScopeSnapshot,
    key: bytes,
    now: Optional[datetime] = None,
) -> Decision:
    try:
        return _authorize(method, url, snapshot, key, now or utcnow())
    except Exception as exc:  # noqa: BLE001 - anything unexpected is a deny, never a pass
        return DENY(f"gate error: {type(exc).__name__}")


def _authorize(method: str, url: str, snapshot: ScopeSnapshot, key: bytes, now: datetime) -> Decision:
    if not isinstance(snapshot, ScopeSnapshot) or not snapshot.is_sealed_with(key):
        return DENY("scope snapshot missing or seal invalid")

    try:
        target = parse_target(url)
    except (ValueError, InvalidDomain) as exc:
        return DENY(f"unparseable or unsafe url: {exc}")

    if target.host not in snapshot.verified_hosts:
        return DENY("host not verified", target.host, target.path)
    if not (snapshot.window_start <= now < snapshot.window_end):
        return DENY("outside scan window", target.host, target.path)

    verb = method.upper() if isinstance(method, str) else ""
    if verb not in KNOWN_METHODS or verb in snapshot.forbidden_methods:
        return DENY("method not permitted", target.host, target.path)
    if any(_under(target.path, d) for d in snapshot.deny_paths):
        return DENY("path on exclusion list", target.host, target.path)
    if not any(_under(target.path, a) for a in snapshot.allow_paths):
        return DENY("path not in allow-list", target.host, target.path)

    return Decision(True, "in scope", target.host, target.path)
