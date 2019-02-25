from web3 import Web3

from raiden.storage.sqlite import SQLiteStorage

SOURCE_VERSION = 18
TARGET_VERSION = 19


def _add_blockhash_to_contract_receive_state_changes(storage: SQLiteStorage, web3: Web3) -> None:
    state_changes = storage.get_all_state_changes(0, 'latest')
    updated_state_changes = []
    for state_change in state_changes:
        if 'raiden.transfer.state_change.ContractReceive' in state_change.data['_type']:
            msg = 'v18 state changes cant contain blockhash'
            assert 'block_hash' not in state_change.data, msg
            block_number = int(state_change['block_number'])
            block_hash = bytes(web3.eth.getBlock(block_number)['hash'])
            state_change['block_hash'] = block_hash

            updated_state_changes.append(state_change)

    storage.update_state_changes(updated_state_changes)


def upgrade_state_changes_with_blockhash(
        storage: SQLiteStorage,
        old_version: int,
        current_version: int,
        web3: Web3,
) -> int:
    if old_version == SOURCE_VERSION:
        _add_blockhash_to_contract_receive_state_changes(storage, web3)

    return TARGET_VERSION
