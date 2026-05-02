from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal


Severity = Literal["critical", "high", "medium", "low"]


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    workflow: str
    job: str | None
    step: str | None
    title: str
    description: str
    recommendation: str
    evidence: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class WorkflowSummary:
    path: str
    triggers: list[str]
    risk_score: int
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "triggers": self.triggers,
            "risk_score": self.risk_score,
            "findings": [finding.to_dict() for finding in self.findings],
        }


@dataclass
class RepoReport:
    repo_name: str
    root: str
    total_findings: int
    risk_score: int
    severity_counts: dict[str, int]
    urgent_fix_queue: list[str]
    workflow_summaries: list[WorkflowSummary]
    repo_recommendations: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "repo_name": self.repo_name,
            "root": self.root,
            "total_findings": self.total_findings,
            "risk_score": self.risk_score,
            "severity_counts": self.severity_counts,
            "urgent_fix_queue": self.urgent_fix_queue,
            "workflow_summaries": [summary.to_dict() for summary in self.workflow_summaries],
            "repo_recommendations": self.repo_recommendations,
        }


def workflow_relative(root: Path, workflow_path: Path) -> str:
    return workflow_path.relative_to(root).as_posix()
