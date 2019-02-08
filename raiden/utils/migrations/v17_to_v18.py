import json

from raiden.exceptions import ChannelNotFound
from raiden.storage.sqlite import SQLiteStorage
from raiden.transfer.state import RouteState
from raiden.utils.typing import Any, Dict, Optional

SOURCE_VERSION = 17
TARGET_VERSION = 18


def get_token_network_by_identifier(
        snapshot: Dict[Any, Any],
        token_network_identifier: str,
) -> Optional[Dict[Any, Any]]:
    identifiers_to_paymentnetworks = snapshot['identifiers_to_paymentnetworks']
    for paymentnetwork in identifiers_to_paymentnetworks.values():
        for token_network in paymentnetwork['tokennetworks']:
            if token_network['address'] == token_network_identifier:
                return token_network
    return None


def _transform_snapshot(raw_snapshot: Dict[Any, Any]) -> str:
    """
    This migration upgrades the object:
    - `MediatorTransferState` such that a list of routes is added
    to the state to be able to route a waiting transfer in case the
    receiving node comes back online.
    """
    snapshot = json.loads(raw_snapshot)
    secrethash_to_task = snapshot['payment_mapping']['secrethashes_to_task']
    for task in secrethash_to_task.values():
        if task['_type'] != 'raiden.transfer.state.MediatorTask':
            continue

        mediator_state = task.get('mediator_state')

        # Make sure the old meditor_state was not migrated already.
        assert 'routes' not in mediator_state

        mediator_state['routes'] = []

        waiting_transfer = mediator_state.get('waiting_transfer')
        if waiting_transfer is None:
            continue

        transfer = waiting_transfer.get('transfer')
        token_network_identifier = transfer['balance_proof']['token_network_identifier']
        token_network = get_token_network_by_identifier(
            snapshot,
            token_network_identifier,
        )
        channel_identifier = transfer['balance_proof']['channel_identifier']
        channel = token_network.get('channelidentifiers_to_channels').get(channel_identifier)
        if not channel:
            raise ChannelNotFound(
                'Upgrading to v18 failed. '
                f'Could not find channel with identifier {channel_identifier} '
                'in the current chain state.',
            )

        # Only add the route for which the waiting transfer was intended.
        # At the time of migration, we cannot re-calculate the list of routes
        # that were originally calculated when the transfer was being
        # mediated so this step should be sufficient for now.
        mediator_state['routes'] = [
            RouteState.from_dict({
                'node_address': channel['partner_state']['address'],
                'channel_identifier': channel_identifier,
            }).to_dict(),
        ]
    return json.dumps(snapshot)


def _add_routes_to_mediator(storage: SQLiteStorage):
    for snapshot in storage.get_snapshots():
        new_snapshot = _transform_snapshot(snapshot.data)
        storage.update_snapshot(snapshot.identifier, new_snapshot)


def upgrade_mediators_with_waiting_transfer(
        storage: SQLiteStorage,
        old_version: int,
        current_version: int,
) -> int:
    if old_version == SOURCE_VERSION:
        _add_routes_to_mediator(storage)

    return TARGET_VERSION
