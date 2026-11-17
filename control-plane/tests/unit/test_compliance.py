from pathlib import Path

import pytest

from app.compliance import mapper
from app.engines.base import RawFinding
from app.engines.nuclei_adapter import TAG_CLASS
from app.engines.zap_adapter import PLUGIN_CLASS
from app.findings.raw_store import save_raw
from app.findings.store import normalize_job

MATRIX = Path(__file__).resolve().parents[3] / "compliance" / "control-matrix.md"


@pytest.mark.parametrize("cls", sorted(mapper.CONTROLS))
def test_every_class_maps_to_all_three_frameworks(cls):
    fw = mapper.frameworks_for(cls)
    assert fw["owasp"] and fw["pci_dss_v4"] and fw["mas_trm"]


def test_every_engine_class_is_mapped():
    # anything an adapter can emit by name must have a real mapping, not the fallback
    emitted = set(PLUGIN_CLASS.values()) | {c for _, c in TAG_CLASS} | {"bola", "broken_auth"}
    assert emitted <= set(mapper.CONTROLS)


def test_cwe_fallback_then_generic():
    assert mapper.control_for("zap_99999", 89)[0] == "sqli"
    cls, c = mapper.control_for("zap_99999", 12345)
    assert cls == "unclassified" and c is mapper.FALLBACK
    fw = mapper.frameworks_for("totally_new")
    assert fw["owasp"] and fw["pci_dss_v4"] and fw["mas_trm"]


def test_bola_mapping_is_the_expected_one():
    fw = mapper.frameworks_for("bola")
    assert fw["owasp"][0].startswith("API1:2023") and "A01:2021 Broken Access Control" in fw["owasp"]
    assert any(x.startswith("7.2.") for x in fw["pci_dss_v4"]) and any("Access Control" in x for x in fw["mas_trm"])


def test_apply_and_coverage_on_real_rows(session):
    save_raw(session, "j", [
        RawFinding(engine="authz", vuln_class="bola", title="t", url="http://h/bookings/Q7X2KD", severity="high"),
        RawFinding(engine="zap", vuln_class="zap_123", title="t", url="http://h/x", severity="low", cwe=79),
        RawFinding(engine="zap", vuln_class="zap_456", title="t", url="http://h/y", severity="low"),
    ])
    rows = normalize_job(session, "j")
    mapper.apply(rows)
    for r in rows:
        assert r.frameworks["owasp"] and r.frameworks["pci_dss_v4"] and r.frameworks["mas_trm"] and r.remediation
    assert {r.frameworks["mapped_as"] for r in rows} == {"bola", "xss", "unclassified"}
    cov = mapper.coverage(rows)
    assert cov["owasp"]["API1:2023 Broken Object Level Authorization"] == 1
    assert sum(cov["pci_dss_v4"].values()) >= 3


def test_coverage_works_on_unstamped_rows():
    class F:
        vuln_class, cwe, frameworks = "bola", None, {}

    assert mapper.coverage([F()])["owasp"]["API1:2023 Broken Object Level Authorization"] == 1


def test_matrix_doc_is_in_sync():
    assert MATRIX.read_text(encoding="utf-8") == mapper.render_matrix(), "regenerate compliance/control-matrix.md"
