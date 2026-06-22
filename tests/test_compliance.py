"""Tests del informe de cumplimiento PCI."""
from core import compliance


def _f(fid, cat, sev, passed=False, page=""):
    return {"id": fid, "category": cat, "severity": sev, "passed": passed,
            "title": fid, "evidence": "", "page": page}


def _report(findings, target="https://shop.example", grade="C", score=70):
    return {"target": target, "grade": grade, "score": score,
            "scanned_at": "2026-06-22 10:00 UTC", "findings": findings}


def test_clean_site_is_compliant():
    a = compliance.assess(_report([]))
    assert a["verdict"] == "Compliant"
    assert a["passing"] == a["total"]
    assert a["gaps"] == 0


def test_monitoring_requirement_always_passes():
    # incluso con agujeros, el requisito de escaneo (11.3.2) pasa: lo estás corriendo
    a = compliance.assess(_report([_f("https", "tls", "critical")]))
    mon = [r for r in a["results"] if r["code"] == "11.3.2"][0]
    assert mon["status"] == "pass"
    assert mon["monitored"] is True


def test_tls_finding_fails_transit_requirement():
    a = compliance.assess(_report([_f("https", "tls", "critical")]))
    req = [r for r in a["results"] if r["code"] == "4.2.1"][0]
    assert req["status"] == "fail"
    assert a["verdict"] == "Non-compliant"


def test_low_severity_is_advisory_not_fail():
    # un hallazgo low no debería tumbar el requisito (queda como advisory)
    a = compliance.assess(_report([_f("referrer-policy", "headers", "low")]))
    req = [r for r in a["results"] if r["code"] == "6.4.2"][0]
    assert req["status"] == "pass"
    assert req["findings"]  # igual se lista como advisory


def test_passed_findings_ignored():
    a = compliance.assess(_report([_f("https", "tls", "critical", passed=True)]))
    assert a["verdict"] == "Compliant"


def test_label_translates_known_ids_to_english():
    assert compliance._label(_f("strict-transport-security", "headers", "high")).startswith("Missing HSTS")
    assert "cookie" in compliance._label(_f("cookie-SESSION", "cookies", "medium")).lower()
    assert compliance._label(_f("sqli-1", "injection", "high")) == "SQL injection"


def test_label_falls_back_to_category():
    assert compliance._label(_f("weird-unknown", "cors", "medium")) == "CORS misconfiguration"


def test_build_html_contains_host_and_verdict():
    html = compliance.build_html(_report([_f("content-security-policy", "headers", "high")]))
    assert "shop.example" in html
    assert "Non-compliant" in html
    assert "PCI DSS" in html
    assert html.lstrip().startswith("<!DOCTYPE html>")


def test_counts_consistent():
    a = compliance.assess(_report([_f("https", "tls", "high"),
                                    _f("content-security-policy", "headers", "high")]))
    assert a["passing"] + a["gaps"] == a["total"]
    assert a["total"] == 6
