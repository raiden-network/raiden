import copy
import json

from raiden.exceptions import RaidenUnrecoverableError
from raiden.network.proxies.utils import get_onchain_locksroots
from raiden.storage.sqlite import SQLiteStorage
from raiden.transfer.state import (
    NettingChannelEndState,
    NettingChannelState,
    TransactionExecutionStatus,
)
from raiden.utils.typing import Any, Dict

RaidenService = 'RaidenService'

SOURCE_VERSION = 19
TARGET_VERSION = 20


def _find_channel_new_state_change(
        storage: SQLiteStorage,
        token_network_address: str,
        channel_identifier: str,
):
    return storage.get_latest_event_by_data_field({
        '_type': 'raiden.transfer.state_change.ContractReceiveChannelNew',
        'token_network_identifier': token_network_address,
        'channel_state.identifier': channel_identifier,
    })


def _add_onchain_locksroot_to_channel_settled_state_changes(
        storage: SQLiteStorage,
) -> None:
    """ Adds `our_onchain_locksroot` and `partner_onchain_locksroot` to
    ContractReceiveChannelSettled. """
    batch_size = 50
    batch_query = storage.batch_query_state_changes(
        batch_size=batch_size,
        filters=[
            ('_type', 'raiden.transfer.state_change.ContractReceiveChannelSettled'),
        ],
    )
    for state_changes_batch in batch_query:
        updated_state_changes = []
        for state_change in state_changes_batch:
            data = json.loads(state_change.data)
            msg = 'v18 state changes cant contain our_onchain_locksroot'
            assert 'our_onchain_locksroot' not in data, msg

            msg = 'v18 state changes cant contain partner_onchain_locksroot'
            assert 'partner_onchain_locksroot' not in data, msg

            data['our_onchain_locksroot'] = None
            data['partner_onchain_locksroot'] = None

            updated_state_changes.append((
                json.dumps(data),
                state_change.state_change_identifier,
            ))
        storage.update_state_changes(updated_state_changes)


def _add_onchain_locksroot_to_snapshot(
        raiden: RaidenService,
        storage: SQLiteStorage,
        raw_snapshot: Dict[str, Any],
):
    """
    Add `onchain_locksroot` to each NettingChannelEndState
    """
    snapshot = json.loads(raw_snapshot)

    for payment_network in snapshot.get('identifiers_to_paymentnetworks', {}).values():
        for token_network in payment_network.get('tokennetworks', []):
            channelidentifiers_to_channels = token_network.get(
                'channelidentifiers_to_channels',
                dict(),
            )
            for channel_identifier, channel in channelidentifiers_to_channels.items():
                channel_new_state_change = _find_channel_new_state_change(
                    storage=storage,
                    token_network_address=token_network['address'],
                    channel_identifier=channel_identifier,
                )

                if not channel_new_state_change:
                    raise RaidenUnrecoverableError(
                        'Could not find the state change for channel {channel_identifier}, '
                        'token network address: {token_network["address"]} being created. ',
                    )

                # Create a dummy channel_state to satisfy the parameter requirements of
                # get_on_chain_locksroots
                channel_copy = copy.deepcopy(channel)

                # Silence `from_dict`-related errors (INTENTIONAL)
                channel_copy['our_state']['onchain_locksroot'] = None
                channel_copy['partner_state']['onchain_locksroot'] = None
                channel_copy['open_transaction'] = TransactionExecutionStatus.from_dict(
                    channel_copy['open_transaction'],
                )

                channel_copy['our_state'] = NettingChannelEndState.from_dict(
                    channel_copy['our_state'],
                )
                channel_copy['partner_state'] = NettingChannelEndState.from_dict(
                    channel_copy['partner_state'],
                )

                channel_state = NettingChannelState.from_dict(channel_copy)
                our_locksroot, partner_locksroot = get_onchain_locksroots(
                    raiden=raiden,
                    channel_state=channel_state,
                    block_hash='latest',
                )

                channel['our_state']['onchain_locksroot'] = our_locksroot
                channel['partner_state']['onchain_locksroot'] = partner_locksroot

    return json.dumps(snapshot, indent=4)


def _add_onchain_locksroot_to_snapshots(
        raiden: RaidenService,
        storage: SQLiteStorage,
):
    updated_snapshots_data = []
    for snapshot in storage.get_snapshots():
        new_snapshot = _add_onchain_locksroot_to_snapshot(raiden, storage, snapshot.data)
        updated_snapshots_data.append((new_snapshot, snapshot.identifier))

    storage.update_snapshots(updated_snapshots_data)


def upgrade_v19_to_v20(
        storage: SQLiteStorage,
        old_version: int,
        current_version: int,
        raiden: 'RaidenService',
        **kwargs,
) -> int:
    if old_version == SOURCE_VERSION:
        _add_onchain_locksroot_to_channel_settled_state_changes(storage)
        _add_onchain_locksroot_to_snapshots(raiden, storage)

    return TARGET_VERSION
