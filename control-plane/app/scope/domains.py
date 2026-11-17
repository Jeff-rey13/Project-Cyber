"""Domain canonicalisation and the loopback check.

Everything that compares hosts goes through `canonical_domain`, so "Nimbus.TEST.",
"nimbus.test" and the punycode form of an IDN all land on one string.
"""

import ipaddress


class InvalidDomain(ValueError):
    pass


def canonical_domain(raw: str) -> str:
    """Return the lowercase, ascii (punycode) form of a bare hostname or ip literal.

    Rejects anything that isn't a bare host: schemes, ports, paths, userinfo,
    whitespace. Callers parsing URLs should strip those first.
    """
    if not isinstance(raw, str):
        raise InvalidDomain("domain must be a string")
    host = raw.strip()
    if host != raw or not host:
        raise InvalidDomain("empty or padded domain")

    # bracketed ipv6 literal
    if host.startswith("[") and host.endswith("]"):
        try:
            return str(ipaddress.IPv6Address(host[1:-1]))
        except ValueError as exc:
            raise InvalidDomain("bad ipv6 literal") from exc
    # bare ipv6 too, so canonical_domain(canonical_domain(x)) == canonical_domain(x)
    if ":" in host:
        try:
            return str(ipaddress.IPv6Address(host))
        except ValueError:
            pass  # falls through to the "not a bare hostname" rejection

    if any(c in host for c in "/:@?#\\ %\t\r\n\x00"):
        raise InvalidDomain("not a bare hostname")

    try:
        return str(ipaddress.IPv4Address(host))
    except ValueError:
        pass

    # one trailing dot is the fqdn form of the same name; ".." is left in so the label check rejects it
    if host.endswith("."):
        host = host[:-1]
    try:
        ascii_host = host.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise InvalidDomain("not a valid idna hostname") from exc

    labels = ascii_host.split(".")
    if len(ascii_host) > 253 or any(not label or len(label) > 63 for label in labels):
        raise InvalidDomain("bad label length")
    if any(label.startswith("-") or label.endswith("-") for label in labels):
        raise InvalidDomain("label starts or ends with a hyphen")
    if not all(c.isalnum() or c == "-" for label in labels for c in label):
        raise InvalidDomain("illegal character in hostname")
    # all-numeric tlds are how decimal/octal ip tricks sneak past a naive parser
    if labels[-1].isdigit():
        raise InvalidDomain("numeric tld")
    return ascii_host


def is_loopback(domain: str) -> bool:
    """True only for literal loopback addresses and the name `localhost`.

    Deliberately never resolves dns: a name that *resolves* to 127.0.0.1 is
    still a name someone else controls (dns rebinding), so it doesn't count.
    """
    if domain == "localhost":
        return True
    try:
        return ipaddress.ip_address(domain).is_loopback
    except ValueError:
        return False
