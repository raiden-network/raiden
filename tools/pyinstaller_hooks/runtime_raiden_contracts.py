import sys
from pathlib import Path

from raiden_contracts import contract_manager

# `sys._MEIPASS` is the root of the extracted pyinstaller bundle
base_path = Path(sys._MEIPASS)  # pylint: disable=no-member

# Patch location of compiled contracts.
contract_manager._BASE = base_path
