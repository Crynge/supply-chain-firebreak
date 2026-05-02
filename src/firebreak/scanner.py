from __future__ import annotations

from pathlib import Path
from typing import Any

from .models import Finding, RepoReport, WorkflowSummary, workflow_relative
from .parser import iter_workflow_files, load_workflow, normalize_triggers
from .rules import (
    SEVERITY_WEIGHT,
    action_owner,
    flatten_env,
    is_pinned_action,
    is_publish_job,
    permission_is_overbroad,
    references_publish_secret,
    references_user_input,
    runs_on_self_hosted,
)


def _effective_permissions(workflow: dict[str, Any], job: dict[str, Any]) -> dict[str, str]:
    permissions: dict[str, str] = {}
    for source in [workflow.get("permissions"), job.get("permissions")]:
        if isinstance(source, dict):
            permissions.update({str(key): str(value) for key, value in source.items()})
        elif isinstance(source, str):
            permissions[source] = source
    return permissions


def _finding(
    *,
    rule_id: str,
    severity: str,
    workflow: str,
    title: str,
    description: str,
    recommendation: str,
    evidence: str,
    job: str | None = None,
    step: str | None = None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,  # type: ignore[arg-type]
        workflow=workflow,
        job=job,
        step=step,
        title=title,
        description=description,
        recommendation=recommendation,
        evidence=evidence,
    )


def scan_repository(root: str | Path, repo_name: str | None = None) -> RepoReport:
    repo_root = Path(root).resolve()
    workflow_paths = iter_workflow_files(repo_root)
    workflow_summaries: list[WorkflowSummary] = []
    all_findings: list[Finding] = []
    has_actions_codeql = False

    for workflow_path in workflow_paths:
        workflow_data = load_workflow(workflow_path)
        workflow_name = workflow_relative(repo_root, workflow_path)
        triggers = normalize_triggers(workflow_data.get("on"))
        workflow_findings: list[Finding] = []
        untrusted_context = bool(set(triggers) & {"pull_request", "pull_request_target", "issue_comment"})

        if "pull_request_target" in triggers:
            workflow_findings.append(
                _finding(
                    rule_id="unsafe-pull-request-target",
                    severity="high",
                    workflow=workflow_name,
                    title="Workflow uses pull_request_target",
                    description="`pull_request_target` runs in the base repository context and has been a recurring root cause in CI/CD compromise chains.",
                    recommendation="Avoid `pull_request_target` for code from forks. Prefer `pull_request`, or isolate privileged jobs behind a separate trusted workflow.",
                    evidence="Trigger list includes pull_request_target.",
                )
            )

        jobs = workflow_data.get("jobs", {})
        if not isinstance(jobs, dict):
            jobs = {}

        for job_id, job_value in jobs.items():
            if not isinstance(job_value, dict):
                continue
            job = job_value
            permissions = _effective_permissions(workflow_data, job)
            job_env = flatten_env(job)
            publish_job = is_publish_job(str(job_id), job)

            for permission_name, permission_value in permissions.items():
                if permission_is_overbroad(permission_name, permission_value):
                    workflow_findings.append(
                        _finding(
                            rule_id="overbroad-permissions",
                            severity="high",
                            workflow=workflow_name,
                            job=str(job_id),
                            title="Job or workflow grants broad write permissions",
                            description="Over-permissioned GitHub tokens increase blast radius when a workflow is compromised.",
                            recommendation="Reduce permissions to the narrowest required set and keep write scopes off untrusted execution paths.",
                            evidence=f"Permission `{permission_name}` is set to `{permission_value}`.",
                        )
                    )

            if runs_on_self_hosted(job.get("runs-on")) and untrusted_context:
                workflow_findings.append(
                    _finding(
                        rule_id="self-hosted-untrusted-runner",
                        severity="critical",
                        workflow=workflow_name,
                        job=str(job_id),
                        title="Untrusted workflow runs on a self-hosted runner",
                        description="Self-hosted runners in PR-style contexts let attacker-controlled code execute inside your infrastructure.",
                        recommendation="Keep self-hosted runners off untrusted events or isolate them behind manual approvals and strong network boundaries.",
                        evidence=f"Job `{job_id}` uses self-hosted runners while workflow triggers include {', '.join(triggers)}.",
                    )
                )

            if publish_job:
                uses_oidc = permissions.get("id-token") == "write"
                if not uses_oidc:
                    workflow_findings.append(
                        _finding(
                            rule_id="missing-oidc-publish",
                            severity="high",
                            workflow=workflow_name,
                            job=str(job_id),
                            title="Publish job lacks OIDC trusted publishing posture",
                            description="Recent package compromises frequently depended on long-lived publish tokens stored as secrets.",
                            recommendation="Move publish jobs to OIDC trusted publishing for npm or PyPI and remove static registry credentials.",
                            evidence=f"Publish-style job `{job_id}` does not request `id-token: write`.",
                        )
                    )

                if references_publish_secret(job_env):
                    workflow_findings.append(
                        _finding(
                            rule_id="long-lived-publish-token",
                            severity="critical",
                            workflow=workflow_name,
                            job=str(job_id),
                            title="Publish job exposes long-lived registry or platform secrets",
                            description="Static package publish tokens are a primary target in modern supply-chain compromises.",
                            recommendation="Replace long-lived secrets with OIDC trusted publishing and rotate any exposed credentials.",
                            evidence=f"Publish job env includes: {job_env}",
                        )
                    )

            for step in job.get("steps", []):
                if not isinstance(step, dict):
                    continue

                step_name = str(step.get("name") or step.get("uses") or step.get("run") or "unnamed-step")
                uses_value = str(step.get("uses", ""))
                run_value = str(step.get("run", ""))
                step_env = flatten_env(step)

                if "github/codeql-action" in uses_value:
                    has_actions_codeql = True

                if uses_value and not is_pinned_action(uses_value):
                    owner = action_owner(uses_value)
                    severity = "high" if owner not in {"actions", "github"} else "medium"
                    workflow_findings.append(
                        _finding(
                            rule_id="unpinned-third-party-action",
                            severity=severity,
                            workflow=workflow_name,
                            job=str(job_id),
                            step=step_name,
                            title="Action is referenced by tag or branch instead of a full commit SHA",
                            description="Floating action references are a common supply-chain pivot because they can change without repository review.",
                            recommendation="Pin external actions to full-length commit SHAs and manage updates through Dependabot or controlled review.",
                            evidence=f"Step uses `{uses_value}`.",
                        )
                    )

                if (
                    "pull_request_target" in triggers
                    and uses_value.startswith("actions/checkout@")
                    and "github.event.pull_request.head" in str(step.get("with", {}))
                ):
                    workflow_findings.append(
                        _finding(
                            rule_id="checkout-pr-head-in-target",
                            severity="critical",
                            workflow=workflow_name,
                            job=str(job_id),
                            step=step_name,
                            title="pull_request_target job checks out attacker-controlled PR head",
                            description="This pattern turns a privileged base-repo workflow into direct execution of untrusted code.",
                            recommendation="Do not combine `pull_request_target` with checkout of PR head content. Split trust boundaries into separate workflows.",
                            evidence=f"Checkout step references PR head in `{uses_value}` with args `{step.get('with', {})}`.",
                        )
                    )

                if run_value and references_user_input(run_value):
                    workflow_findings.append(
                        _finding(
                            rule_id="script-injection-user-input",
                            severity="high",
                            workflow=workflow_name,
                            job=str(job_id),
                            step=step_name,
                            title="Run step interpolates attacker-controlled GitHub event data",
                            description="User-submitted fields like PR titles, bodies, and comments can inject shell content into workflows.",
                            recommendation="Pass untrusted event data through actions that safely escape it, or treat it as data rather than shell code.",
                            evidence=f"Run step contains user input markers: `{run_value}`.",
                        )
                    )

                if untrusted_context and (references_publish_secret(run_value) or references_publish_secret(step_env)):
                    workflow_findings.append(
                        _finding(
                            rule_id="secret-use-in-untrusted-context",
                            severity="critical",
                            workflow=workflow_name,
                            job=str(job_id),
                            step=step_name,
                            title="Secrets appear inside an untrusted workflow path",
                            description="Secrets exposed to PR-style or comment-triggered workflows are a direct secret-exfiltration risk.",
                            recommendation="Keep secrets out of untrusted workflows, or gate privileged jobs behind trusted events and approvals.",
                            evidence=f"Workflow triggers {triggers} and step/job text references secrets.",
                        )
                    )

        risk_score = min(100, sum(SEVERITY_WEIGHT[finding.severity] for finding in workflow_findings))
        all_findings.extend(workflow_findings)
        workflow_summaries.append(
            WorkflowSummary(
                path=workflow_name,
                triggers=triggers,
                risk_score=risk_score,
                findings=workflow_findings,
            )
        )

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in all_findings:
        severity_counts[finding.severity] += 1

    recommendations = [
        "Enable GitHub Actions workflow scanning and keep it mandatory on pull requests.",
        "Move npm and PyPI publishing to OIDC trusted publishing where available.",
        "Pin third-party actions to full commit SHAs and monitor updates deliberately.",
        "Keep secrets and self-hosted runners away from untrusted PR execution paths.",
    ]
    if not has_actions_codeql:
        all_findings.append(
            _finding(
                rule_id="missing-actions-codeql",
                severity="medium",
                workflow="repository-wide",
                job=None,
                step=None,
                title="Repository does not appear to scan GitHub Actions workflows",
                description="GitHub explicitly recommends scanning workflow implementations because recent attacks start there.",
                recommendation="Add CodeQL or equivalent workflow scanning focused on Actions security best practices.",
                evidence="No step references github/codeql-action in the scanned workflow set.",
            )
        )
        severity_counts["medium"] += 1

    urgent_fix_queue = [
        finding.title
        for finding in sorted(all_findings, key=lambda item: (SEVERITY_WEIGHT[item.severity], item.rule_id), reverse=True)[:6]
    ]
    total_risk = min(100, sum(SEVERITY_WEIGHT[finding.severity] for finding in all_findings))

    return RepoReport(
        repo_name=repo_name or repo_root.name,
        root=str(repo_root),
        total_findings=len(all_findings),
        risk_score=total_risk,
        severity_counts=severity_counts,
        urgent_fix_queue=urgent_fix_queue,
        workflow_summaries=workflow_summaries,
        repo_recommendations=recommendations,
    )
