import os
import sys

"""
Tame overeager darwin openssl "fix" in devp2p.crypto which is incompatible with frozen dist.
"""

# flake8: noqa


if sys.platform == 'darwin':
    # This needs to be imported here before the sys.platform hack otherwise the wrong library
    # loading code will be used
    from ctypes.util import find_library

    # Disable special darwin handling in devp2p
    _sys_platform = sys.platform
    sys.platform = 'linux'

    _lib_path = os.environ.get('DYLD_LIBRARY_PATH')
    os.environ['DYLD_LIBRARY_PATH'] = sys.prefix

    from devp2p import crypto

    sys.platform = _sys_platform
    if _lib_path:
        os.environ['DYLD_LIBRARY_PATH'] = _lib_path
    else:
        del os.environ['DYLD_LIBRARY_PATH']
