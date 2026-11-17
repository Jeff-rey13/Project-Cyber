"""Property-based tests for authorize_request: default-deny must hold everywhere.

The strategy is adversarial generation (encodings, traversal, userinfo, ip
forms, unicode) plus an independent oracle: whenever the gate says ALLOW,
we re-derive from scratch that the request really is inside the snapshot.
"""

import ipaddress
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote, urlsplit

from hypothesis import HealthCheck, assume, example, given, settings
from hypothesis import strategies as st

from app.scope.gate import authorize_request
from app.scope.snapshot import ScopeSnapshot

KEY = b"property-test-key-0123456789"
T0 = datetime(2027, 1, 1, tzinfo=timezone.utc)
INSIDE = T0 + timedelta(minutes=30)

VERIFIED = ("127.0.0.1", "nimbus.test")


def make_snapshot(**kw) -> ScopeSnapshot:
    base = dict(
        job_id="job-prop",
        verified_hosts=VERIFIED,
        allow_paths=("/bookings", "/me", "/auth/token", "/openapi.json"),
        deny_paths=("/bookings/admin", "/me/delete"),
        window_start=T0,
        window_end=T0 + timedelta(hours=1),
        forbidden_methods=frozenset({"DELETE", "TRACE", "CONNECT"}),
        proof_ref=(1, 2),
        captured_at=T0,
    )
    base.update(kw)
    snap = ScopeSnapshot(**base)
    import hashlib
    import hmac

    return snap.model_copy(update={"seal": hmac.new(KEY, snap.canonical_bytes(), hashlib.sha256).hexdigest()})


SNAP = make_snapshot()

# --- strategies -------------------------------------------------------------

methods = st.sampled_from(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT", "get", "Get", "FOO", ""])

label = st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789-", min_size=1, max_size=12)
random_domains = st.builds(lambda parts: ".".join(parts), st.lists(label, min_size=1, max_size=4))
ipv4_any = st.integers(0, 2**32 - 1).map(lambda n: str(ipaddress.IPv4Address(n)))
# every spelling of 127.0.0.1 that a sloppy parser might treat as loopback
loopback_tricks = st.sampled_from([
    "2130706433", "0x7f000001", "0177.0.0.1", "0x7f.0.0.1", "127.1", "127.0.1", "017700000001",
    "127.000.000.001", "[::ffff:127.0.0.1]", "[::1]", "localhost", "127.0.0.2", "0.0.0.0", "0",
])
lookalikes = st.sampled_from([
    "nimbus.test.evil.com", "evilnimbus.test", "nimbus-test", "nimbus.tes", "xn--nimbus-.test",
    "nіmbus.test",  # cyrillic i
    "nimbus。test",  # ideographic full stop
    "NIMBUS.TEST.evil", "127.0.0.1.nip.io", "127.0.0.1.evil.com",
])
hosts = st.one_of(random_domains, ipv4_any, loopback_tricks, lookalikes, st.sampled_from(VERIFIED))

ports = st.one_of(st.just(""), st.integers(0, 70000).map(lambda p: f":{p}"), st.sampled_from([":", ":abc", ":80", ":443", ":-1"]))
userinfo = st.one_of(st.just(""), st.sampled_from(["user@", "user:pass@", "127.0.0.1@", "nimbus.test@", "a@b@", "%40@"]))
schemes = st.sampled_from(["http", "https", "HTTP", "ftp", "file", "gopher", "javascript", "", "http:/", "//"])

path_atoms = st.sampled_from([
    "bookings", "me", "admin", "delete", "auth", "token", "openapi.json", "..", ".", "%2e%2e", "%2E%2e",
    "%2f", "%5c", "\\", "%00", "%252e%252e", "..%2f", "ABC123", "", ";", "%20", "bookings%2fadmin", "Bookings",
])
paths = st.builds(lambda segs: "/" + "/".join(segs), st.lists(path_atoms, max_size=6))
suffixes = st.sampled_from(["", "?a=1", "#frag", "?next=http://evil.com", "?x=../../admin"])


@st.composite
def urls(draw):
    return f"{draw(schemes)}://{draw(userinfo)}{draw(hosts)}{draw(ports)}{draw(paths)}{draw(suffixes)}"


arbitrary_text = st.text(max_size=120)
times = st.datetimes(min_value=datetime(2000, 1, 1), max_value=datetime(2100, 1, 1), timezones=st.just(timezone.utc))


# --- independent oracle ------------------------------------------------------

def _decoded(path: str) -> str:
    prev, cur = None, path
    for _ in range(5):
        if prev == cur:
            break
        prev, cur = cur, unquote(cur)
    return cur


def _under(path: str, prefix: str) -> bool:
    if prefix == "/":
        return True
    p = prefix.rstrip("/")
    return path == p or path.startswith(p + "/")


def oracle_in_scope(method: str, url: str, snap: ScopeSnapshot, now: datetime) -> bool:
    """Deliberately naive and conservative re-derivation of 'is this in scope'."""
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return False
    if parts.scheme.lower() not in {"http", "https"} or parts.username is not None or "@" in parts.netloc:
        return False
    host = (parts.hostname or "").rstrip(".").lower()
    if host not in snap.verified_hosts:
        return False
    if port is not None and not (1 <= port <= 65535):
        return False
    if not (snap.window_start <= now < snap.window_end):
        return False
    if method.upper() in snap.forbidden_methods or not method:
        return False
    path = _decoded(parts.path or "/")
    if any(seg in {"..", "."} for seg in path.split("/")) or "\\" in path or "\x00" in path:
        return False
    if any(_under(path, d) for d in snap.deny_paths):
        return False
    return any(_under(path, a) for a in snap.allow_paths)


# --- properties ----------------------------------------------------------------

@settings(max_examples=3000, suppress_health_check=[HealthCheck.too_slow])
@given(method=methods, url=urls())
@example(method="GET", url="http://127.0.0.1@evil.com/bookings")
@example(method="GET", url="http://evil.com@127.0.0.1/bookings")
@example(method="GET", url="http://127.0.0.1/bookings/../bookings/admin")
@example(method="GET", url="http://127.0.0.1/bookings/%2e%2e/bookings/admin")
@example(method="GET", url="http://127.0.0.1/bookings%2fadmin")
@example(method="GET", url="http://2130706433/bookings")
@example(method="GET", url="http://127.0.0.1\\@evil.com/bookings")
def test_allow_implies_in_scope(method, url):
    d = authorize_request(method, url, SNAP, KEY, now=INSIDE)
    if d.allowed:
        assert oracle_in_scope(method, url, SNAP, INSIDE), (method, url, d)


@settings(max_examples=1500)
@given(method=methods, url=arbitrary_text)
def test_arbitrary_text_never_crashes_and_is_mostly_denied(method, url):
    d = authorize_request(method, url, SNAP, KEY, now=INSIDE)
    assert isinstance(d.allowed, bool) and d.reason
    if d.allowed:
        assert oracle_in_scope(method, url, SNAP, INSIDE)


@settings(max_examples=1500)
@given(method=methods, host=st.one_of(random_domains, ipv4_any, loopback_tricks, lookalikes), path=paths)
def test_unverified_hosts_always_denied(method, host, path):
    assume(host.lower().rstrip(".") not in VERIFIED)
    for scheme in ("http", "https"):
        assert not authorize_request(method, f"{scheme}://{host}{path}", SNAP, KEY, now=INSIDE).allowed


@settings(max_examples=500)
@given(method=methods, url=urls(), now=times)
def test_outside_window_always_denied(method, url, now):
    assume(not (SNAP.window_start <= now < SNAP.window_end))
    assert not authorize_request(method, url, SNAP, KEY, now=now).allowed


@settings(max_examples=500)
@given(method=methods, url=urls(), extra=hosts)
def test_tampered_snapshot_always_denied(method, url, extra):
    forged = SNAP.model_copy(update={"verified_hosts": SNAP.verified_hosts + (extra,)})
    assert not authorize_request(method, url, forged, KEY, now=INSIDE).allowed
    assert not authorize_request(method, url, SNAP, b"wrong-key-but-long-enough", now=INSIDE).allowed


@settings(max_examples=500)
@given(url=urls())
def test_forbidden_methods_always_denied(url):
    for m in ("DELETE", "delete", "TRACE", "CONNECT"):
        assert not authorize_request(m, url, SNAP, KEY, now=INSIDE).allowed


@settings(max_examples=1000)
@given(prefix=st.sampled_from(["/bookings/admin", "/me/delete"]), tail=paths, enc=st.sampled_from(["", "%2f", "/./", "//"]))
def test_deny_list_cannot_be_dodged(prefix, tail, enc):
    url = f"http://127.0.0.1{prefix}{enc}{tail}"
    d = authorize_request("GET", url, SNAP, KEY, now=INSIDE)
    if d.allowed:
        assert oracle_in_scope("GET", url, SNAP, INSIDE)


def test_empty_scope_denies_everything():
    empty = make_snapshot(verified_hosts=(), allow_paths=())
    for url in ("http://127.0.0.1/", "http://nimbus.test/bookings", "https://localhost/"):
        assert not authorize_request("GET", url, empty, KEY, now=INSIDE).allowed


def test_sanity_some_requests_are_allowed():
    # guards against a gate that passes the properties by denying everything
    for url in ("http://127.0.0.1/bookings/ABC123", "https://NIMBUS.test./me", "http://127.0.0.1:8080/openapi.json",
                "http://nimbus.test/bookings?pnr=1"):
        assert authorize_request("GET", url, SNAP, KEY, now=INSIDE).allowed, url
    assert authorize_request("POST", "http://127.0.0.1/auth/token", SNAP, KEY, now=INSIDE).allowed
