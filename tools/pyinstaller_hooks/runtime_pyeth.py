import subprocess
import sys

"""
Prevent devp2p, ethereum, and pyethapp form executing git in version check as it causes a
confusing popup on macOS when developer tools aren't installed.
"""

# flake8: noqa


if sys.platform == 'darwin':
    _check_output = subprocess.check_output
    subprocess.check_output = lambda *a, **kw: ""

    import ethereum

    subprocess.check_output = _check_output
