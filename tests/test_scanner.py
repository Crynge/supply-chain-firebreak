from pathlib import Path

from firebreak.reporting import write_html_report
from firebreak.scanner import scan_repository


ROOT = Path(__file__).resolve().parents[1]


def test_vulnerable_fixture_triggers_critical_findings() -> None:
    report = scan_repository(ROOT / "fixtures" / "vulnerable-repo", repo_name="vulnerable-repo")

    assert report.risk_score > 80
    assert report.severity_counts["critical"] >= 2
    assert any("pull_request_target" in item.lower() or "checks out attacker-controlled" in item.lower() for item in report.urgent_fix_queue)


def test_secure_fixture_is_significantly_lower_risk() -> None:
    report = scan_repository(ROOT / "fixtures" / "secure-repo", repo_name="secure-repo")

    assert report.risk_score < 30
    assert report.severity_counts["critical"] == 0


def test_html_report_generation() -> None:
    report = scan_repository(ROOT / "fixtures" / "vulnerable-repo", repo_name="vulnerable-repo")
    destination = ROOT / "results" / "test-report.html"
    write_html_report(report, destination)

    html = destination.read_text(encoding="utf-8")
    assert "Supply Chain Firebreak HTML report" in html
    assert "vulnerable-repo" in html
