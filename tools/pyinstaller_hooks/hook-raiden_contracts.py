import os
from pathlib import Path

from raiden_contracts.contract_manager import _BASE

datas = []


for subdir, _, _ in os.walk(_BASE):
    for file_path in Path(subdir).glob('*.json'):
        datas.append(
            (
                str(file_path),
                os.path.basename(subdir),
            ),
        )
