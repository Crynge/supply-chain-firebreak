from __future__ import annotations

import re
from typing import Any


USER_INPUT_MARKERS = [
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.pull_request.head.ref",
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.comment.body",
    "github.event.head_commit.message",
]

PUBLISH_SECRET_MARKERS = [
    "NPM_TOKEN",
    "NODE_AUTH_TOKEN",
    "PYPI_API_TOKEN",
    "TWINE_PASSWORD",
    "TWINE_USERNAME",
    "GITHUB_TOKEN",
]

SEVERITY_WEIGHT = {
    "critical": 28,
    "high": 18,
    "medium": 9,
    "low": 4,
}


def is_pinned_action(action_ref: str) -> bool:
    if action_ref.startswith("./"):
        return True
    if "@" not in action_ref:
        return False
    version = action_ref.split("@", 1)[1]
    return bool(re.fullmatch(r"[0-9a-fA-F]{40}", version))


def action_owner(action_ref: str) -> str:
    if action_ref.startswith("./"):
        return "local"
    slug = action_ref.split("@", 1)[0]
    return slug.split("/", 1)[0]


def is_publish_job(job_id: str, job: dict[str, Any]) -> bool:
    haystacks = [job_id.lower(), str(job.get("name", "")).lower()]
    for step in job.get("steps", []):
        if isinstance(step, dict):
            haystacks.append(str(step.get("name", "")).lower())
            haystacks.append(str(step.get("run", "")).lower())
            haystacks.append(str(step.get("uses", "")).lower())
    joined = " ".join(haystacks)
    keywords = ["publish", "release", "npm publish", "twine upload", "gh-action-pypi-publish", "deploy"]
    return any(keyword in joined for keyword in keywords)


def references_user_input(run_text: str) -> bool:
    return any(marker in run_text for marker in USER_INPUT_MARKERS)


def references_publish_secret(text: str) -> bool:
    return any(marker in text for marker in PUBLISH_SECRET_MARKERS) or "secrets." in text.lower()


def runs_on_self_hosted(runs_on: Any) -> bool:
    if isinstance(runs_on, str):
        return "self-hosted" in runs_on.lower()
    if isinstance(runs_on, list):
        return any("self-hosted" in str(item).lower() for item in runs_on)
    return False


def permission_is_overbroad(permission_name: str, permission_value: str) -> bool:
    if permission_value == "write-all":
        return True
    return permission_name in {"actions", "contents", "packages"} and permission_value == "write"


def flatten_env(job_or_step: dict[str, Any]) -> str:
    env = job_or_step.get("env", {})
    if not isinstance(env, dict):
        return ""
    return " ".join(f"{key}={value}" for key, value in env.items())
