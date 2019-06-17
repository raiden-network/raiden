import os

from raiden.utils.typing import Optional


def get_artifacts_storage(*parts) -> Optional[str]:
    artifact_dir = os.environ.get("RAIDEN_TESTS_ETH_LOGSDIR")

    if artifact_dir:
        os.path.join(artifact_dir, *parts)

    return None
