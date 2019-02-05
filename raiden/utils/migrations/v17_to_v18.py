import json
import sqlite3

from raiden.exceptions import RaidenDBUpgradeError
from raiden.transfer.state import RouteState
from raiden.utils.typing import Any, Dict


def get_snapshots(cursor: sqlite3.Cursor):
    cursor.execute('SELECT identifier, data FROM state_snapshot')
    snapshots = cursor.fetchall()
    for snapshot in snapshots:
        yield snapshot[0], snapshot[1]


def update_snapshot(
        cursor: sqlite3.Cursor,
        identifier: int,
        new_snapshot: Dict[Any, Any],
):
    cursor.execute(
        'UPDATE state_snapshot SET data=? WHERE identifier=?',
        (new_snapshot, identifier),
    )


def get_token_network_by_identifier(snapshot, token_network_identifier):
    identifiers_to_paymentnetworks = snapshot['identifiers_to_paymentnetworks']
    for paymentnetwork in identifiers_to_paymentnetworks.values():
        for token_network in paymentnetwork['tokennetworks']:
            if token_network['address'] == token_network_identifier:
                return token_network
    return None


def _transform_snapshot(raw_snapshot: Dict[Any, Any]):
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

        # The migration should be idempotent.
        if 'routes' in mediator_state:
            continue

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
            raise RaidenDBUpgradeError(
                'Upgrading to v18 failed. '
                f'Could not find channel with identifier {channel_identifier} '
                'in the current chain state.',
            )

        # Only add the route for which the waiting transfer was intended.
        # At the time of migration, we cannot re-calculate the list of routes
        # that were originally calculcated when the transfer was being
        # mediated so this step should be sufficient for now.
        mediator_state['routes'] = [
            RouteState.from_dict({
                'node_address': channel['partner_state']['address'],
                'channel_identifier': channel_identifier,
            }).to_dict(),
        ]
    return json.dumps(snapshot)


def _add_routes_to_mediator(cursor: sqlite3.Cursor):
    for identifier, snapshot in get_snapshots(cursor):
        new_snapshot = _transform_snapshot(snapshot)
        update_snapshot(cursor, identifier, new_snapshot)


def upgrade_mediators_with_waiting_transfer(
        cursor: sqlite3.Cursor,
        old_version: int,
        current_version: int,
):
    if current_version > 17:
        _add_routes_to_mediator(cursor)
