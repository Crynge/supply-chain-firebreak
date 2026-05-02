from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


class GitHubActionsLoader(yaml.SafeLoader):
    """YAML loader that preserves GitHub Actions keys like `on` as strings."""


for first_letter, mappings in list(GitHubActionsLoader.yaml_implicit_resolvers.items()):
    GitHubActionsLoader.yaml_implicit_resolvers[first_letter] = [
        (tag, regexp)
        for tag, regexp in mappings
        if tag != "tag:yaml.org,2002:bool"
    ]


def load_workflow(path: Path) -> dict[str, Any]:
    content = yaml.load(path.read_text(encoding="utf-8"), Loader=GitHubActionsLoader) or {}
    if not isinstance(content, dict):
        return {}
    return content


def normalize_triggers(raw_triggers: Any) -> list[str]:
    if isinstance(raw_triggers, str):
        return [raw_triggers]
    if isinstance(raw_triggers, list):
        return [str(item) for item in raw_triggers]
    if isinstance(raw_triggers, dict):
        return [str(key) for key in raw_triggers.keys()]
    return []


def iter_workflow_files(root: Path) -> list[Path]:
    workflow_dir = root / ".github" / "workflows"
    if not workflow_dir.exists():
        return []
    return sorted([*workflow_dir.glob("*.yml"), *workflow_dir.glob("*.yaml")])
