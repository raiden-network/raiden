import sys
from pathlib import Path

from raiden_contracts import contract_manager

# `sys._MEIPASS` is the root of the extracted pyinstaller bundle
base_path = Path(sys._MEIPASS)

# Patch location of compiled contracts.
contract_manager.CONTRACTS_PRECOMPILED_PATH = base_path.joinpath('contracts.json.gz')
contract_manager.CONTRACT_MANAGER = contract_manager.ContractManager(
    contract_manager.CONTRACTS_PRECOMPILED_PATH,
)
