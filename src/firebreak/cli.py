from __future__ import annotations

import argparse
from pathlib import Path

from .reporting import write_html_report, write_json_report
from .scanner import scan_repository


def main() -> None:
    parser = argparse.ArgumentParser(description="Scan GitHub Actions workflows for supply-chain firebreak risks.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan a repository")
    scan_parser.add_argument("path")
    scan_parser.add_argument("--repo-name", default=None)
    scan_parser.add_argument("--json-out", default=None)
    scan_parser.add_argument("--html-out", default=None)

    args = parser.parse_args()

    if args.command == "scan":
        report = scan_repository(args.path, repo_name=args.repo_name)
        if args.json_out:
            Path(args.json_out).parent.mkdir(parents=True, exist_ok=True)
            write_json_report(report, args.json_out)
        if args.html_out:
            Path(args.html_out).parent.mkdir(parents=True, exist_ok=True)
            write_html_report(report, args.html_out)

        print(f"Scanned {report.repo_name}")
        print(f"Risk score: {report.risk_score}/100")
        print(f"Findings: {report.total_findings}")
        print("Severity counts:")
        for severity, count in report.severity_counts.items():
            print(f"  {severity}: {count}")


if __name__ == "__main__":
    main()
