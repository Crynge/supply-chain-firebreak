from __future__ import annotations

import json
from pathlib import Path

from .models import RepoReport


def write_json_report(report: RepoReport, destination: str | Path) -> None:
    Path(destination).write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")


def write_html_report(report: RepoReport, destination: str | Path) -> None:
    rows = []
    for workflow in report.workflow_summaries:
        for finding in workflow.findings:
            rows.append(
                f"""
                <tr>
                  <td><span class="pill pill-{finding.severity}">{finding.severity}</span></td>
                  <td>{finding.workflow}</td>
                  <td>{finding.job or "-"}</td>
                  <td>{finding.title}</td>
                  <td>{finding.evidence}</td>
                </tr>
                """
            )

    html = f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>{report.repo_name} · Supply Chain Firebreak</title>
    <style>
      body {{
        margin: 0;
        font-family: "Segoe UI", sans-serif;
        background: #071118;
        color: #edf4f1;
      }}
      main {{
        max-width: 1180px;
        margin: 0 auto;
        padding: 32px;
      }}
      .hero, .card {{
        background: linear-gradient(180deg, rgba(9,17,27,0.96), rgba(11,19,31,0.88));
        border: 1px solid rgba(127,155,164,0.18);
        border-radius: 24px;
        padding: 24px;
        box-shadow: 0 18px 60px rgba(0,0,0,0.25);
      }}
      .hero {{
        display: grid;
        gap: 12px;
      }}
      h1, h2 {{
        margin: 0;
      }}
      .grid {{
        display: grid;
        grid-template-columns: repeat(4, minmax(0, 1fr));
        gap: 16px;
        margin: 20px 0;
      }}
      .metric {{
        background: rgba(13,24,36,0.8);
        border-radius: 18px;
        padding: 16px;
        border: 1px solid rgba(127,155,164,0.12);
      }}
      table {{
        width: 100%;
        border-collapse: collapse;
      }}
      th, td {{
        padding: 12px 10px;
        text-align: left;
        border-bottom: 1px solid rgba(127,155,164,0.12);
        vertical-align: top;
      }}
      .pill {{
        display: inline-block;
        padding: 6px 10px;
        border-radius: 999px;
        font-size: 12px;
        text-transform: uppercase;
      }}
      .pill-critical {{ background: rgba(219,92,92,0.18); color: #ffbeb8; }}
      .pill-high {{ background: rgba(245,183,66,0.18); color: #ffd89c; }}
      .pill-medium {{ background: rgba(90,176,255,0.18); color: #bce0ff; }}
      .pill-low {{ background: rgba(46,215,153,0.18); color: #aaf6d7; }}
      ul {{ padding-left: 18px; }}
    </style>
  </head>
  <body>
    <main>
      <section class="hero">
        <p>Supply Chain Firebreak HTML report</p>
        <h1>{report.repo_name}</h1>
        <p>Risk score: {report.risk_score} / 100</p>
      </section>
      <section class="grid">
        <div class="metric"><strong>{report.total_findings}</strong><div>Total findings</div></div>
        <div class="metric"><strong>{report.severity_counts["critical"]}</strong><div>Critical</div></div>
        <div class="metric"><strong>{report.severity_counts["high"]}</strong><div>High</div></div>
        <div class="metric"><strong>{report.severity_counts["medium"]}</strong><div>Medium</div></div>
      </section>
      <section class="card">
        <h2>Urgent fix queue</h2>
        <ul>{"".join(f"<li>{item}</li>" for item in report.urgent_fix_queue)}</ul>
      </section>
      <section class="card" style="margin-top:20px;">
        <h2>Findings</h2>
        <table>
          <thead>
            <tr>
              <th>Severity</th>
              <th>Workflow</th>
              <th>Job</th>
              <th>Title</th>
              <th>Evidence</th>
            </tr>
          </thead>
          <tbody>
            {"".join(rows)}
          </tbody>
        </table>
      </section>
    </main>
  </body>
</html>
"""
    Path(destination).write_text(html, encoding="utf-8")
