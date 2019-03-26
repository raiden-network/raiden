import json
from functools import partial

from gevent.pool import Pool

from raiden.exceptions import RaidenUnrecoverableError
from raiden.network.proxies.utils import get_onchain_locksroots
from raiden.storage.sqlite import SQLiteStorage, StateChangeRecord
from raiden.utils.typing import Any, Dict, Locksroot, Tuple

RaidenService = 'RaidenService'

SOURCE_VERSION = 19
TARGET_VERSION = 20


def _find_channel_new_state_change(
        storage: SQLiteStorage,
        token_network_address: str,
        channel_identifier: str,
) -> StateChangeRecord:
    return storage.get_latest_event_by_data_field({
        '_type': 'raiden.transfer.state_change.ContractReceiveChannelNew',
        'token_network_identifier': token_network_address,
        'channel_state.identifier': channel_identifier,
    })


def _get_onchain_locksroots(
        raiden: RaidenService,
        storage: SQLiteStorage,
        token_network: Dict[str, Any],
        channel: Dict[str, Any],
) -> Tuple[Locksroot, Locksroot]:
    channel_new_state_change = _find_channel_new_state_change(
        storage=storage,
        token_network_address=token_network['address'],
        channel_identifier=channel['identifier'],
    )

    if not channel_new_state_change:
        raise RaidenUnrecoverableError(
            f'Could not find the state change for channel {channel["identifier"]}, '
            f'token network address: {token_network["address"]} being created. ',
        )

    our_locksroot, partner_locksroot = get_onchain_locksroots(
        raiden=raiden,
        token_network_address=token_network['address'],
        channel_identifier=channel['identifier'],
        participant1=channel['our_state']['address'],
        participant2=channel['partner_state']['address'],
        block_identifier='latest',
    )
    return our_locksroot, partner_locksroot


def _add_onchain_locksroot_to_channel_settled_state_changes(
        raiden: RaidenService,
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
        updated_state_changes = list()
        for state_change in state_changes_batch:
            data = json.loads(state_change.data)
            msg = 'v18 state changes cant contain our_onchain_locksroot'
            assert 'our_onchain_locksroot' not in data, msg

            msg = 'v18 state changes cant contain partner_onchain_locksroot'
            assert 'partner_onchain_locksroot' not in data, msg

            state_change_data = json.loads(state_change.data)
            token_network_identifier = state_change_data['token_network_identifier']
            channel_identifier = state_change_data['channel_identifier']

            channel_new_state_change = _find_channel_new_state_change(
                storage=storage,
                token_network_address=token_network_identifier,
                channel_identifier=channel_identifier,
            )

            if not channel_new_state_change.data:
                raise RaidenUnrecoverableError(
                    f'Could not find the state change for channel {channel_identifier}, '
                    f'token network address: {token_network_identifier} being created. ',
                )

            channel_state_data = json.loads(channel_new_state_change.data)
            new_channel_state = channel_state_data['channel_state']
            our_locksroot, partner_locksroot = get_onchain_locksroots(
                raiden=raiden,
                token_network_address=token_network_identifier,
                channel_identifier=channel_identifier,
                participant1=new_channel_state['our_state']['address'],
                participant2=new_channel_state['partner_state']['address'],
                block_identifier='latest',
            )

            data['our_onchain_locksroot'] = our_locksroot
            data['partner_onchain_locksroot'] = partner_locksroot

            updated_state_changes.append((
                json.dumps(data),
                state_change.state_change_identifier,
            ))
        storage.update_state_changes(updated_state_changes)


def _add_onchain_locksroot_to_snapshot(
        raiden: RaidenService,
        storage: SQLiteStorage,
        snapshot_record: StateChangeRecord,
) -> str:
    """
    Add `onchain_locksroot` to each NettingChannelEndState
    """
    snapshot = json.loads(snapshot_record.data)

    for payment_network in snapshot.get('identifiers_to_paymentnetworks', dict()).values():
        for token_network in payment_network.get('tokennetworks', list()):
            channelidentifiers_to_channels = token_network.get(
                'channelidentifiers_to_channels',
                dict(),
            )
            for channel in channelidentifiers_to_channels.values():
                our_locksroot, partner_locksroot = _get_onchain_locksroots(
                    raiden=raiden,
                    storage=storage,
                    token_network=token_network,
                    channel=channel,
                )
                channel['our_state']['onchain_locksroot'] = our_locksroot
                channel['partner_state']['onchain_locksroot'] = partner_locksroot

    return json.dumps(snapshot, indent=4), snapshot_record.identifier


def _add_onchain_locksroot_to_snapshots(
        raiden: RaidenService,
        storage: SQLiteStorage,
) -> None:
    snapshots = storage.get_snapshots()

    transform_func = partial(
        _add_onchain_locksroot_to_snapshot,
        raiden,
        storage,
    )

    pool_generator = Pool(len(snapshots)).imap(
        transform_func,
        snapshots,
    )

    updated_snapshots_data = []
    for result in pool_generator:
        updated_snapshots_data.append(result)

    storage.update_snapshots(updated_snapshots_data)


def upgrade_v19_to_v20(
        storage: SQLiteStorage,
        old_version: int,
        current_version: int,
        raiden: 'RaidenService',
        **kwargs,
) -> int:
    if old_version == SOURCE_VERSION:
        _add_onchain_locksroot_to_channel_settled_state_changes(raiden, storage)
        _add_onchain_locksroot_to_snapshots(raiden, storage)

    return TARGET_VERSION
