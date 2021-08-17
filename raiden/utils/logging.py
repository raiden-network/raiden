from copy import deepcopy

from raiden.utils.typing import Dict


def redact_secret(data: Dict) -> Dict:
    """Modify `data` and replace keys named `secret`."""
    if not isinstance(data, dict):
        raise ValueError("data must be a dict.")

    # FIXME: assess performance impact of this deepcopy
    data_copy = deepcopy(data)
    stack = [data_copy]

    while stack:
        current = stack.pop()

        if "secret" in current:
            current["secret"] = "<redacted>"
        else:
            stack.extend(value for value in current.values() if isinstance(value, dict))

    return data_copy
