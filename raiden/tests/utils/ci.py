import os
from typing import Optional

from raiden.utils import pex


def get_artifacts_storage() -> Optional[str]:
    return os.environ.get("RAIDEN_TESTS_LOGSDIR")


def shortened_artifacts_storage(test_node) -> Optional[str]:
    """Return a pathname based on the test details.

    Some platforms have a limit to the length of a file path. This function
    will compute a path name based on the test details, and if necessary trim
    it down to fit 300 characters.
    """
    artifacts_dir = get_artifacts_storage()

    if artifacts_dir is None:
        return None

    path = os.path.join(artifacts_dir, test_node.name)

    # Paths longer than 286 will be reject on CircleCI
    if len(path) >= 286:
        original_name = test_node.originalname
        shortened_args = pex(test_node.name.encode("utf8"))
        path = os.path.join(artifacts_dir, f"{original_name}-{shortened_args}")

    msg = (
        "Trimming the tests arguments didn't result in a path short enough, the "
        "base_dir has to be trimmed."
    )
    assert len(path) < 286, msg

    return path
