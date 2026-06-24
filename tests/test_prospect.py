"""Tests del motor de prospección (funciones puras, sin red)."""
from core import prospect


def _f(fid, cat, sev, passed=False):
    return {"id": fid, "category": cat, "severity": sev, "passed": passed,
            "title": fid, "evidence": "", "page": ""}


def _report(findings):
    return {"target": "https://shop.example", "grade": "C", "score": 68,
            "scanned_at": "2026-06-22 10:00 UTC", "counts": {}, "findings": findings}


def test_slug_sanitizes_host():
    assert prospect._slug("Shop.Example.com") == "shop.example.com"
    assert "/" not in prospect._slug("a/b?c")


def test_top_finding_picks_most_severe():
    rep = _report([_f("a", "headers", "low"), _f("b", "tls", "critical"),
                   _f("c", "cookies", "medium")])
    top = prospect._top_finding(rep)
    assert top["id"] == "b"


def test_top_finding_none_when_clean():
    assert prospect._top_finding(_report([])) is None
    # los passed no cuentan
    assert prospect._top_finding(_report([_f("x", "tls", "high", passed=True)])) is None


def test_build_email_has_host_pci_and_top():
    from core import compliance
    rep = _report([_f("strict-transport-security", "headers", "high")])
    a = compliance.assess(rep, "pci")
    email = prospect.build_email("shop.example", rep, a, sender="Santi")
    assert "shop.example" in email
    assert "Subject:" in email
    assert "Santi" in email
    assert f"{a['passing']} of {a['total']}" in email
    assert "HSTS" in email  # el top finding traducido al inglés


def test_email_handles_clean_site():
    from core import compliance
    rep = _report([])
    a = compliance.assess(rep, "pci")
    email = prospect.build_email("clean.example", rep, a)
    assert "clean.example" in email
