#!/usr/bin/env python3
"""
Helper to check if the tool versions specified in the pre-commit config file
match the general project requirements.
"""

import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional

import click
import yaml
from packaging.requirements import Requirement
from packaging.version import Version, parse

PRE_COMMIT_CONFG_PATH = Path(".pre-commit-config.yaml")
REQUIREMENTS_DEV_PATH = Path("requirements", "requirements-dev.txt")


@dataclass(frozen=True)
class ToolConfig:
    name: str
    url: str


class Tool(Enum):
    BLACK = ToolConfig(name="black", url="https://github.com/python/black")
    FLAKE8 = ToolConfig(name="flake8", url="https://gitlab.com/PyCQA/flake8")
    ISORT = ToolConfig(name="isort", url="git://github.com/pre-commit/mirrors-isort")
    MYPY = ToolConfig(name="mypy", url="https://github.com/pre-commit/mirrors-mypy")
    PYLINT = ToolConfig(name="pylint", url="https://github.com/PyCQA/pylint")


@dataclass
class ToolVersion:
    tool: Tool
    version: Version
    additional_deps: List[Requirement] = field(default_factory=list)


_TOOL_BY_REPO_URL: Dict[str, Tool] = {tool.value.url: tool for tool in Tool}


def _find_path_from_project_root(path_fragment: Path) -> Optional[Path]:
    parents = Path(__file__).resolve().parent.parents
    for parent in parents:
        config_file = parent.joinpath(path_fragment)
        if config_file.exists():
            return config_file
    return None


def find_pre_commit_config_file() -> Path:
    config_file = _find_path_from_project_root(PRE_COMMIT_CONFG_PATH)
    if config_file is None:
        raise ValueError("No pre-commit config file found in any parent directory.")
    return config_file


def parse_pre_commit_config_tool_versions(config_file: Path) -> List[ToolVersion]:
    parsed_config = yaml.safe_load(config_file.read_text())
    tool_versions = []
    for repo in parsed_config["repos"]:
        tool = _TOOL_BY_REPO_URL.get(repo["repo"])
        if tool is None:
            continue
        additional_deps = []
        for hook in repo["hooks"]:
            if hook["id"] == tool.value.name:
                for additional_dep in hook.get("additional_dependencies", []):
                    additional_deps.append(Requirement(additional_dep))
        tool_versions.append(
            ToolVersion(
                tool=tool,
                version=parse(repo["rev"]),
                additional_deps=additional_deps,
            )
        )
    return tool_versions


def find_requirements_dev_file() -> Path:
    req_file = _find_path_from_project_root(REQUIREMENTS_DEV_PATH)
    if req_file is None:
        raise ValueError(
            f"Requirements file '{REQUIREMENTS_DEV_PATH!s}' not found in any parent directory."
        )
    return req_file


def parse_requirements_dev(requirements_dev_path: Path) -> Dict[str, Requirement]:
    with requirements_dev_path.open("rt") as requirements_file:
        requirements = {}
        for line in requirements_file:
            requirement_str, *_ = line.strip().partition("#")
            if requirement_str:
                requirement = Requirement(requirement_str)
                requirements[requirement.name] = requirement
    return requirements


def check_pre_commit_tool_versions(
    tool_versions: List[ToolVersion], requirements: Dict[str, Requirement]
) -> List[str]:
    errors = []
    for tool_version in tool_versions:
        tool = tool_version.tool.value
        tool_requirement = requirements.get(tool.name)
        if tool_requirement is None:
            errors.append(f"No project requirement for tool '{tool.name}' found.")
            continue
        if tool_version.version not in tool_requirement.specifier:
            errors.append(
                f"Tool '{tool.name}' ({tool_version.version}) is out of sync with project "
                f"requirement ({tool_requirement.specifier})."
            )
        for additional_dep in tool_version.additional_deps:
            specifiers = list(additional_dep.specifier)
            if len(specifiers) != 1 or specifiers[0].operator != "==":
                errors.append(
                    f"Can only process a single strict equality constraint for "
                    f"'additional_dependencies' (in '{tool.name}' -> '{additional_dep}')"
                )
                continue
            additional_dep_requirement = requirements.get(additional_dep.name)
            if additional_dep_requirement is None:
                errors.append(
                    f"Can't find additional dependency '{additional_dep}' of '{tool.name}' in "
                    f"project requirements."
                )
                continue
            if Version(specifiers[0].version) not in additional_dep_requirement.specifier:
                errors.append(
                    f"Additional dependency '{additional_dep}' of '{tool.name}' is out of sync "
                    f"with project requirement '{additional_dep_requirement}'."
                )
                continue
    return errors


@click.command()
def main() -> None:
    tool_versions = parse_pre_commit_config_tool_versions(find_pre_commit_config_file())
    project_requirements = parse_requirements_dev(find_requirements_dev_file())
    errors = check_pre_commit_tool_versions(tool_versions, project_requirements)
    if errors:
        click.secho("pre-commit config is out of sync!", fg="red")
        click.echo("  - ", nl=False)
        click.echo("\n  - ".join(click.style(error, fg="yellow") for error in errors))
        sys.exit(1)


if __name__ == "__main__":
    main()
