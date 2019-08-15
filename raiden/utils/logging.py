from raiden.utils.typing import Dict


def redact_secret(data: Dict) -> Dict:
    """ Modify `data` in-place and replace keys named `secret`. """
    if not isinstance(data, dict):
        raise ValueError("data must be a dict.")

    stack = [data]

    while stack:
        current = stack.pop()

        if "secret" in current:
            current["secret"] = "<redacted>"
        else:
            stack.extend(value for value in current.values() if isinstance(value, dict))

    return data
