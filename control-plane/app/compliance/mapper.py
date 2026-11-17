"""Finding -> control mapping across OWASP, PCI DSS v4.0 and MAS TRM (PRD 6.5).

One table, keyed by our vuln_class. compliance/control-matrix.md is generated
from it (`python -m app.compliance.mapper`) so the doc and the code can't drift.

Reference granularity is deliberate:
  - OWASP API Top 10 2023 / OWASP Top 10 2021: category ids.
  - PCI DSS v4.0: requirement numbers.
  - MAS TRM Guidelines (Jan 2021): chapter-level. Sub-clause numbers should be
    checked against the published text before this goes in front of an auditor.
MAS TRM is written for financial institutions; here it's used as the Singapore
regulatory benchmark for an airline that takes payments and runs loyalty.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class Control:
    owasp_api: tuple[str, ...]
    owasp_web: tuple[str, ...]
    pci_dss_v4: tuple[str, ...]
    mas_trm: tuple[str, ...]
    remediation: str


API = {
    "API1": "API1:2023 Broken Object Level Authorization",
    "API2": "API2:2023 Broken Authentication",
    "API3": "API3:2023 Broken Object Property Level Authorization",
    "API4": "API4:2023 Unrestricted Resource Consumption",
    "API6": "API6:2023 Unrestricted Access to Sensitive Business Flows",
    "API8": "API8:2023 Security Misconfiguration",
    "API9": "API9:2023 Improper Inventory Management",
}
WEB = {
    "A01": "A01:2021 Broken Access Control",
    "A02": "A02:2021 Cryptographic Failures",
    "A03": "A03:2021 Injection",
    "A04": "A04:2021 Insecure Design",
    "A05": "A05:2021 Security Misconfiguration",
    "A07": "A07:2021 Identification and Authentication Failures",
}
PCI = {
    "2.2.1": "2.2.1 Configuration standards defined and applied",
    "3.4.1": "3.4.1 PAN masked when displayed",
    "4.2.1": "4.2.1 Strong cryptography for PAN in transit",
    "6.2.4": "6.2.4 Engineering techniques prevent common software attacks",
    "6.4.1": "6.4.1 Public-facing web apps protected against attacks",
    "7.2.1": "7.2.1 Access control model defined",
    "7.2.2": "7.2.2 Access assigned on least privilege",
    "8.2.1": "8.2.1 Unique ID for every user",
    "8.3.1": "8.3.1 All user access authenticated",
    "8.3.4": "8.3.4 Invalid authentication attempts limited",
    "12.5.1": "12.5.1 Inventory of in-scope system components",
}
MAS = {
    "5": "MAS TRM 5 Software Application Development and Management",
    "7": "MAS TRM 7 IT Resilience",
    "8": "MAS TRM 8 Access Control",
    "9": "MAS TRM 9 Cryptography",
    "10": "MAS TRM 10 Data and Infrastructure Security",
    "11": "MAS TRM 11 Cyber Security Operations",
    "13": "MAS TRM 13 Online Financial Services",
}


def _c(api, web, pci, mas, fix) -> Control:
    return Control(tuple(API[x] for x in api), tuple(WEB[x] for x in web), tuple(PCI[x] for x in pci), tuple(MAS[x] for x in mas), fix)


CONTROLS: dict[str, Control] = {
    "bola": _c(["API1"], ["A01"], ["7.2.1", "7.2.2", "6.2.4"], ["8", "10"],
               "Check that the caller owns the object on every request, server-side, before loading it. "
               "Answer 404 for 'not yours' so the endpoint isn't an existence oracle."),
    "broken_auth": _c(["API2"], ["A07"], ["8.2.1", "8.3.1", "6.2.4"], ["8", "13"],
                      "Require a verified, signed, unexpired credential on every non-public endpoint; never treat a "
                      "record locator or other guessable value as proof of identity."),
    "excessive_data_exposure": _c(["API3"], ["A01", "A04"], ["3.4.1", "7.2.2", "6.2.4"], ["10"],
                                  "Return an explicit response schema per use case; drop DOB, passport and payment "
                                  "fields from itinerary lookups."),
    "mass_assignment": _c(["API3"], ["A01", "A04"], ["7.2.2", "6.2.4"], ["8", "5"],
                          "Bind requests to an allow-listed input model and reject unknown fields; privileged "
                          "attributes like role and loyalty tier are never client-writable."),
    "missing_rate_limit": _c(["API4", "API6"], ["A04"], ["8.3.4", "6.4.1"], ["7", "13"],
                             "Rate-limit lookup and authentication endpoints per client and per identity; alert on "
                             "enumeration patterns."),
    "sqli": _c(["API8"], ["A03"], ["6.2.4", "6.4.1"], ["5"],
               "Use parameterised queries throughout; never build sql from request data."),
    "xss": _c(["API8"], ["A03"], ["6.2.4", "6.4.1"], ["5"],
              "Context-aware output encoding plus a restrictive Content-Security-Policy."),
    "ssi": _c(["API8"], ["A03"], ["6.2.4"], ["5"], "Disable server-side includes and encode user input."),
    "path_traversal": _c(["API8"], ["A01", "A03"], ["6.2.4"], ["5", "10"],
                         "Resolve paths against a fixed base and reject anything that escapes it."),
    "rfi": _c(["API8"], ["A03"], ["6.2.4"], ["5"], "Never include or fetch resources named by user input."),
    "csrf": _c(["API8"], ["A01"], ["6.2.4"], ["5"], "Use anti-csrf tokens or SameSite cookies for state-changing requests."),
    "missing_security_header": _c(["API8"], ["A05"], ["2.2.1", "6.4.1"], ["10"],
                                  "Set HSTS, X-Content-Type-Options, a CSP and frame protection at the edge."),
    "security_misconfiguration": _c(["API8"], ["A05"], ["2.2.1"], ["10"],
                                    "Harden configuration from a documented baseline and check drift."),
    "loose_cookie": _c(["API8"], ["A05", "A07"], ["2.2.1", "6.2.4"], ["10"],
                       "Mark session cookies Secure, HttpOnly and SameSite."),
    "info_disclosure": _c(["API8"], ["A05"], ["2.2.1", "6.2.4"], ["10"],
                          "Strip version banners, stack traces and debug output from responses."),
    "pii_disclosure": _c(["API3"], ["A01", "A02"], ["3.4.1", "7.2.2"], ["10", "9"],
                         "Minimise personal data in responses and mask what must be shown."),
    "api_inventory_exposure": _c(["API9"], ["A05"], ["12.5.1", "2.2.1"], ["5", "10"],
                                 "Keep an api inventory; don't publish the schema of internal or partner apis publicly."),
    "cleartext_transport": _c(["API8"], ["A02"], ["4.2.1"], ["9"], "Serve only over TLS 1.2+ and redirect http."),
}

# when an engine reports a class we don't know, fall back on cwe, then on a generic secure-sdlc mapping
CWE_CLASS = {
    79: "xss", 89: "sqli", 22: "path_traversal", 98: "rfi", 352: "csrf", 200: "info_disclosure", 359: "pii_disclosure",
    639: "bola", 284: "bola", 306: "broken_auth", 287: "broken_auth", 915: "mass_assignment", 770: "missing_rate_limit",
    307: "missing_rate_limit", 693: "missing_security_header", 16: "security_misconfiguration", 319: "cleartext_transport",
    1004: "loose_cookie", 614: "loose_cookie",
}
FALLBACK = _c(["API8"], ["A05"], ["6.2.4"], ["5"],
              "Triage manually; the issue maps to general secure-development and configuration controls.")


def control_for(vuln_class: str, cwe: Optional[int] = None) -> tuple[str, Control]:
    if vuln_class in CONTROLS:
        return vuln_class, CONTROLS[vuln_class]
    if cwe in CWE_CLASS:
        cls = CWE_CLASS[cwe]
        return cls, CONTROLS[cls]
    return "unclassified", FALLBACK


def frameworks_for(vuln_class: str, cwe: Optional[int] = None) -> dict[str, list[str]]:
    _, c = control_for(vuln_class, cwe)
    return {"owasp": list(c.owasp_api + c.owasp_web), "pci_dss_v4": list(c.pci_dss_v4), "mas_trm": list(c.mas_trm)}


def apply(findings) -> None:
    """Stamp frameworks + remediation onto normalized Finding rows (in place)."""
    for f in findings:
        mapped, c = control_for(f.vuln_class, f.cwe)
        f.frameworks = {**frameworks_for(f.vuln_class, f.cwe), "mapped_as": mapped}
        f.remediation = c.remediation


def coverage(findings) -> dict[str, dict[str, int]]:
    """framework -> control -> finding count; feeds the dashboard heatmap."""
    out: dict[str, dict[str, int]] = {"owasp": {}, "pci_dss_v4": {}, "mas_trm": {}}
    for f in findings:
        fw = f.frameworks or frameworks_for(f.vuln_class, f.cwe)
        for key in out:
            for ctrl in fw.get(key, []):
                out[key][ctrl] = out[key].get(ctrl, 0) + 1
    return out


def render_matrix() -> str:
    lines = [
        "# Control matrix",
        "",
        "Generated from `control-plane/app/compliance/mapper.py`. Do not edit by hand; run",
        "`python -m app.compliance.mapper > ../compliance/control-matrix.md` from `control-plane/`.",
        "",
        "PCI DSS references are v4.0 requirement numbers. MAS TRM references are chapter-level",
        "(Guidelines, January 2021) and should be confirmed against the published sub-clauses before",
        "external use. MAS TRM targets financial institutions; it is applied here as the Singapore",
        "regulatory benchmark for an airline handling payments and loyalty value.",
        "",
        "| Finding class | OWASP API 2023 | OWASP Top 10 2021 | PCI DSS v4.0 | MAS TRM | Remediation |",
        "|---|---|---|---|---|---|",
    ]
    for cls, c in sorted(CONTROLS.items()):
        lines.append("| `{}` | {} | {} | {} | {} | {} |".format(
            cls, "<br>".join(c.owasp_api), "<br>".join(c.owasp_web), "<br>".join(c.pci_dss_v4), "<br>".join(c.mas_trm), c.remediation))
    lines.append("| *(unclassified)* | {} | {} | {} | {} | {} |".format(
        "<br>".join(FALLBACK.owasp_api), "<br>".join(FALLBACK.owasp_web), "<br>".join(FALLBACK.pci_dss_v4),
        "<br>".join(FALLBACK.mas_trm), FALLBACK.remediation))
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    import sys

    sys.stdout.reconfigure(encoding="utf-8")
    sys.stdout.write(render_matrix())
