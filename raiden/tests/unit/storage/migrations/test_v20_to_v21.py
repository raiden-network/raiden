import json
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

from raiden.storage.migrations.v20_to_v21 import upgrade_v20_to_v21
from raiden.storage.sqlite import SQLiteStorage
from raiden.utils.upgrades import UpgradeManager, UpgradeRecord


def setup_storage(db_path):
    storage = SQLiteStorage(str(db_path))

    state_changes_file = Path(__file__).parent / "data/v20_statechanges.json"
    state_changes_data = json.loads(state_changes_file.read_text())
    for state_change_record in state_changes_data:
        storage.write_state_change(
            state_change=json.dumps(state_change_record[1]),
            log_time=datetime.utcnow().isoformat(timespec="milliseconds"),
        )

    chain_state_data = Path(__file__).parent / "data/v20_chainstate.json"
    chain_state = chain_state_data.read_text()
    cursor = storage.conn.cursor()
    cursor.execute(
        """
        INSERT INTO state_snapshot(identifier, statechange_id, data)
        VALUES(1, 1, ?)
        """,
        (chain_state,),
    )
    storage.conn.commit()
    return storage


def assert_state_changes_are_transformed(storage: SQLiteStorage) -> None:
    batch_query = storage.batch_query_state_changes(
        batch_size=50,
        filters=[("_type", "raiden.transfer.state_change.ContractReceiveChannelNew")],
    )

    for state_changes_batch in batch_query:
        for state_change in state_changes_batch:
            data = json.loads(state_change.data)
            msg = "mediation_fee should have been added to channel_state"
            assert "mediation_fee" in data["channel_state"], msg

            msg = "mediation_fee should have an initial value of 0"
            assert data["channel_state"]["mediation_fee"] == "0", msg

    batch_query = storage.batch_query_state_changes(
        batch_size=50,
        filters=[("_type", "raiden.transfer.mediated_transfer.state_change.ActionInitInitiator")],
    )

    for state_changes_batch in batch_query:
        for state_change in state_changes_batch:
            data = json.loads(state_change.data)

            msg = "allocated_fee should been added to ActionInitInitiator"
            assert "allocated_fee" in data["transfer"], msg

            msg = "allocated_fee should have an initial value of 0"
            assert data["transfer"]["allocated_fee"] == "0", msg


def assert_snapshots_are_transformed(storage: SQLiteStorage) -> None:
    _, snapshot = storage.get_latest_state_snapshot()
    assert snapshot is not None

    snapshot = json.loads(snapshot)

    tn_to_pn = snapshot["tokennetworkaddresses_to_paymentnetworkaddresses"]
    for payment_network in snapshot["identifiers_to_paymentnetworks"].values():
        for token_network in payment_network["tokennetworks"]:
            msg = (
                f'{payment_network["address"]} should exist in the chain state\'s '
                f"tokennetworkaddresses_to_paymentnetworkaddresses member",
            )
            assert token_network["address"] in tn_to_pn, msg

            msg = (
                f'Address of Payment network: {payment_network["address"]} does not equal '
                f'the address in the token network: {token_network["address"]}',
            )
            assert tn_to_pn[token_network["address"]] == payment_network["address"], msg

    for task in snapshot["payment_mapping"]["secrethashes_to_task"].values():
        if "raiden.transfer.state.InitiatorTask" in task["_type"]:
            for initiator in task["manager_state"]["initiator_transfers"].values():
                msg = "allocated_fee was not initialized in the initiator transfer description"
                assert initiator["transfer_description"]["allocated_fee"] == "0", msg

    for payment_network in snapshot["identifiers_to_paymentnetworks"].values():
        for token_network in payment_network["tokennetworks"]:
            for channel_state in token_network["channelidentifiers_to_channels"].values():
                channel_state["mediation_fee"] = "0"


def test_upgrade_v20_to_v21(tmp_path):
    old_db_filename = tmp_path / Path("v20_log.db")
    with patch("raiden.utils.upgrades.latest_db_file") as latest_db_file:
        latest_db_file.return_value = str(old_db_filename)
        storage = setup_storage(str(old_db_filename))
        with patch("raiden.storage.sqlite.RAIDEN_DB_VERSION", new=20):
            storage.update_version()
        storage.conn.close()

    db_path = tmp_path / Path("v21_log.db")
    manager = UpgradeManager(db_filename=str(db_path))
    with patch(
        "raiden.utils.upgrades.UPGRADES_LIST",
        new=[UpgradeRecord(from_version=20, function=upgrade_v20_to_v21)],
    ):
        manager.run()

    storage = SQLiteStorage(str(db_path))

    assert_state_changes_are_transformed(storage)
    assert_snapshots_are_transformed(storage)
