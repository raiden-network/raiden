import json
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock, patch

from raiden.storage.migrations.v19_to_v20 import upgrade_v19_to_v20
from raiden.storage.sqlite import SQLiteStorage
from raiden.tests.utils.factories import make_32bytes, make_address
from raiden.tests.utils.mocks import MockRaidenService
from raiden.utils.serialization import serialize_bytes
from raiden.utils.upgrades import UpgradeManager, UpgradeRecord


def setup_storage(db_path):
    storage = SQLiteStorage(str(db_path))

    state_changes_file = Path(__file__).parent / 'data/v19_statechanges.json'
    state_changes_data = json.loads(state_changes_file.read_text())
    for state_change_record in state_changes_data:
        storage.write_state_change(
            state_change=json.dumps(state_change_record[1]),
            log_time=datetime.utcnow().isoformat(timespec='milliseconds'),
        )

    # Add the v19 events to the DB
    events_file = Path(__file__).parent / 'data/v19_events.json'
    events_data = json.loads(events_file.read_text())
    event_tuples = []
    for event in events_data:
        state_change_identifier = event[1]
        event_data = json.dumps(event[2])
        log_time = datetime.utcnow().isoformat(timespec='milliseconds')
        event_tuples.append((
            None,
            state_change_identifier,
            log_time,
            event_data,
        ))
    storage.write_events(event_tuples)

    chain_state_data = Path(__file__).parent / 'data/v19_chainstate.json'
    chain_state = chain_state_data.read_text()
    cursor = storage.conn.cursor()
    cursor.execute(
        """
        INSERT INTO state_snapshot(identifier, statechange_id, data)
        VALUES(1, 1, ?)
        """, (chain_state,),
    )
    storage.conn.commit()
    return storage


def test_upgrade_v19_to_v20(tmp_path):
    old_db_filename = tmp_path / Path('v19_log.db')
    with patch('raiden.utils.upgrades.older_db_file') as older_db_file:
        older_db_file.return_value = str(old_db_filename)
        storage = setup_storage(str(old_db_filename))
        with patch('raiden.storage.sqlite.RAIDEN_DB_VERSION', new=19):
            storage.update_version()
        storage.conn.close()

    raiden_service_mock = MockRaidenService()

    our_onchain_locksroot = serialize_bytes(make_32bytes())
    partner_onchain_locksroot = serialize_bytes(make_32bytes())

    details = Mock()
    details.our_details.address = make_address()
    details.our_details.locksroot = our_onchain_locksroot
    details.partner_details.address = make_address()
    details.partner_details.locksroot = partner_onchain_locksroot

    payment_channel = Mock()
    payment_channel.token_network.detail_participants.return_value = details

    payment_channel_func = Mock()
    payment_channel_func.return_value = payment_channel

    raiden_service_mock.chain.payment_channel = payment_channel_func

    db_path = tmp_path / Path('v20_log.db')
    manager = UpgradeManager(db_filename=str(db_path), raiden=raiden_service_mock)
    with patch(
            'raiden.utils.upgrades.UPGRADES_LIST',
            new=[UpgradeRecord(from_version=19, function=upgrade_v19_to_v20)],
    ):
        manager.run()

    storage = SQLiteStorage(str(db_path))

    batch_query = storage.batch_query_state_changes(
        batch_size=500,
        filters=[
            ('_type', 'raiden.transfer.state_change.ContractReceiveChannelSettled'),
        ],
    )
    for state_changes_batch in batch_query:
        for state_change_record in state_changes_batch:
            data = json.loads(state_change_record.data)
            assert data['our_onchain_locksroot'] is not None
            assert data['partner_onchain_locksroot'] is not None

    batch_query = storage.batch_query_event_records(
        batch_size=500,
        filters=[('_type', 'events.ContractSendChannelBatchUnlock')],
    )
    for events_batch in batch_query:
        for event_record in events_batch:
            data = json.loads(event_record.data)
            assert 'partner' in data

    _, snapshot = storage.get_latest_state_snapshot()
    assert snapshot is not None

    snapshot = json.loads(snapshot)

    for payment_network in snapshot['identifiers_to_paymentnetworks'].values():
        for token_network in payment_network['tokennetworks']:
            for channel in token_network['channelidentifiers_to_channels'].values():
                channel_our_locksroot = channel['our_state']['onchain_locksroot']
                channel_partner_locksroot = channel['partner_state']['onchain_locksroot']
                assert channel_our_locksroot == our_onchain_locksroot
                assert channel_partner_locksroot == partner_onchain_locksroot
