import os.path
import sys

from PyInstaller.utils.hooks import get_module_file_attribute

from raiden.utils.typing import List, Tuple

binaries: List[Tuple[str, str]] = []

if sys.platform == "win32":
    coincurve_dir = os.path.dirname(get_module_file_attribute("coincurve"))
    binaries.append((os.path.join(coincurve_dir, "libsecp256k1.dll"), "coincurve"))
