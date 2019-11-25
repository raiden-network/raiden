#!/usr/bin/env python3
"""
This is a small helper to run pylint and mypy with the Raiden dev requirements installed in the
pre-commit generated hook virtualenv.
This is necessary since both pylint and mypy need access to the third party library source files
in order to function correctly.

To speed up the hook runtime we generate and store a hash of the requirements-dev file and only
(re-)run pip-sync if that hash has changed.

The reason to have this at all instead of a repo-local pre-commit hook is that it's difficult to
ensure the project virtualenv is always available during pre-commit execution.
Git GUI clients, editor / IDE integrations, etc. all can cause the virtualenv to not be active
when pre-commit is being executed.
"""

import hashlib
import os
import subprocess
import sys
import sysconfig
from pathlib import Path

REQUIREMENTS_FILE = "requirements/requirements-dev.txt"
REQUIREMENTS_HASH_FILE_NAME = "_RAIDEN_REQUIREMENTS_HASH.txt"


def _get_file_hash(file: Path) -> str:
    if not file.exists():
        raise ValueError(f"File {file} doesn't exist")
    return hashlib.sha256(file.read_bytes()).hexdigest()


def _ensure_requirements() -> None:
    requirements_file_path = Path(REQUIREMENTS_FILE)
    # This path is inside the pre-commit generated virtualenv and therefore will automatically
    # be invalidated if that virtualenv is re-created.
    data_path_str = sysconfig.get_path("data")
    if data_path_str is None:
        raise RuntimeError("No sysconfig data path available.")
    data_path = Path(data_path_str)
    requirements_hash_file = data_path.joinpath(REQUIREMENTS_HASH_FILE_NAME)

    stored_requirements_hash = ""
    if requirements_hash_file.exists():
        stored_requirements_hash = requirements_hash_file.read_text().strip()

    requirements_hash = _get_file_hash(requirements_file_path)

    if stored_requirements_hash != requirements_hash:
        print(
            "Requirements have changed. Updating virtualenv.",
            requirements_hash_file,
            requirements_hash,
        )
        subprocess.check_output(
            [
                sys.executable,
                "-c",
                "from piptools.scripts.sync import cli; cli()",
                REQUIREMENTS_FILE,
            ],
            stderr=subprocess.STDOUT,
        )
        requirements_hash_file.write_text(requirements_hash)


def main() -> None:
    _ensure_requirements()

    # cwd is set to the project root by pre-commit.
    # Add it to sys.path so pylint can find the project local plugins.
    sys.path.insert(0, os.getcwd())

    tool = sys.argv.pop(1)
    if tool == "pylint":
        from pylint import run_pylint

        run_pylint()
    elif tool == "mypy":
        from mypy.__main__ import console_entry

        console_entry()
    else:
        raise RuntimeError(f"Unsupported tool: {tool}")


if __name__ == "__main__":
    main()
