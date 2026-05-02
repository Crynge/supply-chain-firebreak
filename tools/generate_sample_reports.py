from __future__ import annotations

from pathlib import Path

from firebreak.reporting import write_html_report, write_json_report
from firebreak.scanner import scan_repository


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    vulnerable_root = root / "fixtures" / "vulnerable-repo"
    secure_root = root / "fixtures" / "secure-repo"
    public_dir = root / "apps" / "web" / "public"
    results_dir = root / "results"

    public_dir.mkdir(parents=True, exist_ok=True)
    results_dir.mkdir(parents=True, exist_ok=True)

    vulnerable_report = scan_repository(vulnerable_root, repo_name="vulnerable-repo")
    secure_report = scan_repository(secure_root, repo_name="secure-repo")

    write_json_report(vulnerable_report, public_dir / "vulnerable-report.json")
    write_json_report(secure_report, public_dir / "secure-report.json")
    write_json_report(vulnerable_report, results_dir / "vulnerable-report.json")
    write_json_report(secure_report, results_dir / "secure-report.json")
    write_html_report(vulnerable_report, results_dir / "vulnerable-report.html")
    write_html_report(secure_report, results_dir / "secure-report.html")


if __name__ == "__main__":
    main()
