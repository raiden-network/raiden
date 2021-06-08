import pytest
from eth_utils import keccak

from raiden.api.python import RaidenAPI
from raiden.constants import DeviceIDs, RoutingMode
from raiden.messages.abstract import Message
from raiden.messages.decode import balanceproof_from_envelope
from raiden.messages.path_finding_service import PFSCapacityUpdate, PFSFeeUpdate
from raiden.messages.transfers import Unlock
from raiden.raiden_service import RaidenService
from raiden.settings import MediationFeeConfig
from raiden.tests.utils.detect_failure import raise_on_failure
from raiden.tests.utils.factories import make_transaction_hash
from raiden.tests.utils.network import CHAIN
from raiden.tests.utils.transfer import (
    assert_succeeding_transfer_invariants,
    block_timeout_for_transfer_by_secrethash,
    transfer,
    wait_assert,
)
from raiden.tests.utils.transport import TestMatrixTransport
from raiden.transfer import views
from raiden.transfer.state import TransactionChannelDeposit
from raiden.transfer.state_change import ContractReceiveChannelDeposit, ReceiveUnlock
from raiden.utils.typing import (
    List,
    LockedAmount,
    Locksroot,
    MessageID,
    Nonce,
    PaymentAmount,
    PaymentID,
    Secret,
    Signature,
    TokenAddress,
    TokenAmount,
    WithdrawAmount,
)
from raiden.waiting import wait_for_block


def get_messages(app: RaidenService) -> List[Message]:
    assert isinstance(
        app.transport, TestMatrixTransport
    ), "Transport is not a `TestMatrixTransport`"

    return app.transport.broadcast_messages[DeviceIDs.PFS.value]


def reset_messages(app: RaidenService) -> None:
    assert isinstance(
        app.transport, TestMatrixTransport
    ), "Transport is not a `TestMatrixTransport`"

    app.transport.broadcast_messages[DeviceIDs.PFS.value] = []


def wait_all_apps(raiden_network: List[RaidenService]) -> None:
    last_known_block = max(app.rpc_client.block_number() for app in raiden_network)

    for app in raiden_network:
        wait_for_block(app, last_known_block, 0.5)


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [3])
@pytest.mark.parametrize("channels_per_node", [0])
@pytest.mark.parametrize("routing_mode", [RoutingMode.PFS])
def test_pfs_send_capacity_updates_on_deposit_and_withdraw(
    raiden_network: List[RaidenService], token_addresses: List[TokenAddress], pfs_mock
) -> None:
    """
    We need to test if PFSCapacityUpdates and PFSFeeUpdates are being
    sent after a deposit and withdraw.

    The nodes open a channel but do not deposit. After deposit and
    withdraw it is checked that the correct messages are sent.
    """
    app0, app1, app2 = raiden_network
    pfs_mock.add_apps(raiden_network)

    api0 = RaidenAPI(app0)
    api0.channel_open(
        token_address=token_addresses[0],
        registry_address=app0.default_registry.address,
        partner_address=app1.address,
    )
    wait_all_apps(raiden_network)

    # There should be no messages sent at channel opening
    assert len(get_messages(app0)) == 0
    assert len(get_messages(app1)) == 0
    assert len(get_messages(app2)) == 0

    api0.set_total_channel_deposit(
        token_address=token_addresses[0],
        registry_address=app0.default_registry.address,
        partner_address=app1.address,
        total_deposit=TokenAmount(10),
    )
    wait_all_apps(raiden_network)

    # We expect a PFSCapacityUpdate and a PFSFeeUpdate after the deposit
    messages0 = get_messages(app0)
    assert len(messages0) == 2
    assert len([x for x in messages0 if isinstance(x, PFSCapacityUpdate)]) == 1
    assert len([x for x in messages0 if isinstance(x, PFSFeeUpdate)]) == 1

    # We expect the same messages for the target
    messages1 = get_messages(app1)
    assert len(messages1) == 2
    assert len([x for x in messages1 if isinstance(x, PFSCapacityUpdate)]) == 1
    assert len([x for x in messages1 if isinstance(x, PFSFeeUpdate)]) == 1

    # Unrelated node should not send updates
    assert len(get_messages(app2)) == 0

    api0.set_total_channel_withdraw(
        token_address=token_addresses[0],
        registry_address=app0.default_registry.address,
        partner_address=app1.address,
        total_withdraw=WithdrawAmount(5),
    )
    wait_all_apps(raiden_network)

    # We expect a PFSCapacityUpdate and a PFSFeeUpdate after the withdraw
    messages0 = get_messages(app0)
    assert len(messages0) == 4
    assert len([x for x in messages0 if isinstance(x, PFSCapacityUpdate)]) == 2
    assert len([x for x in messages0 if isinstance(x, PFSFeeUpdate)]) == 2

    # We expect the same messages for the target
    messages1 = get_messages(app1)
    assert len(messages1) == 4
    assert len([x for x in messages1 if isinstance(x, PFSCapacityUpdate)]) == 2
    assert len([x for x in messages1 if isinstance(x, PFSFeeUpdate)]) == 2

    # Unrelated node should not send updates
    assert len(get_messages(app2)) == 0


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [3])
@pytest.mark.parametrize("channels_per_node", [CHAIN])
@pytest.mark.parametrize("routing_mode", [RoutingMode.PFS])
def test_pfs_send_capacity_updates_during_mediated_transfer(
    raiden_network: List[RaidenService], number_of_nodes, deposit, token_addresses, network_wait
):
    """
    Tests that PFSCapacityUpdates and PFSFeeUpdates are being
    sent during a mediated transfer.
    """
    app0, app1, app2 = raiden_network
    token_address = token_addresses[0]
    chain_state = views.state_from_raiden(app0)
    token_network_registry_address = app0.default_registry.address
    token_network_address = views.get_token_network_address_by_token_address(
        chain_state, token_network_registry_address, token_address
    )

    # There have been two PFSCapacityUpdates and two PFSFeeUpdates per channel per node
    assert len(get_messages(app0)) == 4
    # The mediator has two channels
    assert len(get_messages(app1)) == 8
    assert len(get_messages(app2)) == 4

    # Reset message lists for more understandable assertions
    reset_messages(app0)
    reset_messages(app1)
    reset_messages(app2)

    amount = PaymentAmount(10)

    secrethash = transfer(
        initiator_app=app0,
        target_app=app2,
        token_address=token_address,
        amount=amount,
        identifier=PaymentID(1),
        timeout=network_wait * number_of_nodes,
        routes=[[app0, app1, app2]],
    )

    with block_timeout_for_transfer_by_secrethash(app1, secrethash):
        wait_assert(
            assert_succeeding_transfer_invariants,
            token_network_address,
            app0,
            deposit - amount,
            [],
            app1,
            deposit + amount,
            [],
        )

    with block_timeout_for_transfer_by_secrethash(app1, secrethash):
        wait_assert(
            assert_succeeding_transfer_invariants,
            token_network_address,
            app1,
            deposit - amount,
            [],
            app2,
            deposit + amount,
            [],
        )

    # Initiator: we expect one PFSCapacityUpdate when locking and one when unlocking
    messages0 = get_messages(app0)
    assert len(messages0) == 2
    assert len([x for x in messages0 if isinstance(x, PFSCapacityUpdate)]) == 2
    assert len([x for x in messages0 if isinstance(x, PFSFeeUpdate)]) == 0

    # Mediator:
    #   incoming channel: we expect one PFSCapacityUpdate when locking and one when unlocking
    #   outgoing channel: we expect one PFSCapacityUpdate when funds are unlocked
    messages1 = get_messages(app1)
    assert len(messages1) == 3
    assert len([x for x in messages1 if isinstance(x, PFSCapacityUpdate)]) == 3
    assert len([x for x in messages1 if isinstance(x, PFSFeeUpdate)]) == 0

    # Target: we expect one PFSCapacityUpdate when funds are unlocked
    messages2 = get_messages(app2)
    assert len(messages2) == 1
    assert len([x for x in messages2 if isinstance(x, PFSCapacityUpdate)]) == 1
    assert len([x for x in messages2 if isinstance(x, PFSFeeUpdate)]) == 0


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [2])
@pytest.mark.parametrize("channels_per_node", [CHAIN])
@pytest.mark.parametrize("routing_mode", [RoutingMode.PFS])
def test_pfs_send_unique_capacity_and_fee_updates_during_mediated_transfer(raiden_network):
    """
    Tests that PFSCapacityUpdates and PFSFeeUpdates are being
    sent only once with the most recent state change in a batch.
    """
    app0, app1 = raiden_network
    chain_state = views.state_from_raiden(app0)

    # There have been two PFSCapacityUpdates and two PFSFeeUpdates per channel per node
    assert len(get_messages(app0)) == 4
    # The mediator has two channels
    assert len(get_messages(app1)) == 4

    # Now we create two state_changes (Deposit) regarding the same channel
    # and trigger handle_state_changes() of node0. The expected outcome
    # is that only 1 PFSCapacityUpdate and 1 PFSFeeUpdate is being sent
    # not one per state change
    pfs_fee_update_1_of_app0 = get_messages(app0)[1]
    assert isinstance(pfs_fee_update_1_of_app0, PFSFeeUpdate)
    pfs_capacity_update_2_of_app0 = get_messages(app0)[2]
    assert isinstance(pfs_capacity_update_2_of_app0, PFSCapacityUpdate)
    canonical_identifier = pfs_fee_update_1_of_app0.canonical_identifier
    new_total_deposit_1 = pfs_capacity_update_2_of_app0.other_capacity * 2

    deposit_transaction_1 = TransactionChannelDeposit(
        app1.address, TokenAmount(new_total_deposit_1), chain_state.block_number
    )
    channel_deposit_1 = ContractReceiveChannelDeposit(
        transaction_hash=make_transaction_hash(),
        canonical_identifier=canonical_identifier,
        deposit_transaction=deposit_transaction_1,
        block_number=chain_state.block_number,
        block_hash=chain_state.block_hash,
        fee_config=MediationFeeConfig(),
    )

    new_total_deposit_2 = new_total_deposit_1 * 2
    deposit_transaction_2 = TransactionChannelDeposit(
        app1.address, TokenAmount(new_total_deposit_2), chain_state.block_number
    )

    channel_deposit_2 = ContractReceiveChannelDeposit(
        transaction_hash=make_transaction_hash(),
        canonical_identifier=canonical_identifier,
        deposit_transaction=deposit_transaction_2,
        block_number=chain_state.block_number,
        block_hash=chain_state.block_hash,
        fee_config=MediationFeeConfig(),
    )

    state_changes = [channel_deposit_1, channel_deposit_2]

    app0.handle_state_changes(state_changes=state_changes)

    # Now we should see that app0 send 2 new messages,
    # one PFSCapacityUpdate and one PFSFeeUpdate with
    # the updated amount of the initial amount * 4
    # so sending should only be triggered by the second state change

    pfs_capacity_update_3_of_app0 = get_messages(app0)[4]
    assert isinstance(pfs_capacity_update_3_of_app0, PFSCapacityUpdate)
    assert len(get_messages(app0)) == 6
    assert (
        pfs_capacity_update_3_of_app0.other_capacity
        == pfs_capacity_update_2_of_app0.updating_capacity * 4
    )

    # Now we want to test if this also works with a state_change
    # that triggers only a PFSCapacityUpdate and no PFSFeeUpdate.
    # So at the end we expect 1 more PFSCapacityUpdate in the room.

    lock_secret_1 = keccak(b"test_end_state")
    unlock_message_1 = Unlock(
        chain_id=chain_state.chain_id,
        message_identifier=MessageID(123132),
        payment_identifier=PaymentID(1),
        nonce=Nonce(2),
        token_network_address=canonical_identifier.token_network_address,
        channel_identifier=canonical_identifier.channel_identifier,
        transferred_amount=TokenAmount(400),
        locked_amount=LockedAmount(0),
        locksroot=Locksroot(keccak(b"")),
        secret=Secret(lock_secret_1),
        signature=Signature(bytes(65)),
    )
    unlock_message_1.sign(app1.signer)
    balance_proof_1 = balanceproof_from_envelope(unlock_message_1)

    unlock_1 = ReceiveUnlock(
        message_identifier=MessageID(5135),
        secret=Secret(lock_secret_1),
        balance_proof=balance_proof_1,
        sender=balance_proof_1.sender,
    )

    lock_secret_2 = keccak(b"test_end_state_again")

    unlock_message_2 = Unlock(
        chain_id=chain_state.chain_id,
        message_identifier=MessageID(223132),
        payment_identifier=PaymentID(2),
        nonce=Nonce(2),
        token_network_address=canonical_identifier.token_network_address,
        channel_identifier=canonical_identifier.channel_identifier,
        transferred_amount=TokenAmount(500),
        locked_amount=LockedAmount(0),
        locksroot=Locksroot(keccak(b"")),
        secret=Secret(lock_secret_2),
        signature=Signature(bytes(65)),
    )

    unlock_message_2.sign(app1.signer)

    balance_proof_2 = balanceproof_from_envelope(unlock_message_2)

    unlock_2 = ReceiveUnlock(
        message_identifier=MessageID(5135),
        secret=Secret(lock_secret_2),
        balance_proof=balance_proof_2,
        sender=balance_proof_2.sender,
    )

    state_changes_2 = [unlock_1, unlock_2]

    app0.handle_state_changes(state_changes=state_changes_2)

    assert len(get_messages(app0)) == 7
    assert len([x for x in get_messages(app0) if isinstance(x, PFSCapacityUpdate)]) == 4
