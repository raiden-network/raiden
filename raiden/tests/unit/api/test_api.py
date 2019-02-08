from raiden.api.python import transfer_tasks_view
from raiden.tests.utils import factories
from raiden.transfer.mediated_transfer.state import (
    InitiatorPaymentState,
    InitiatorTransferState,
    MediationPairState,
    MediatorTransferState,
    TargetTransferState,
    TransferDescriptionWithSecretState,
    WaitingTransferState,
)
from raiden.transfer.state import InitiatorTask, MediatorTask, TargetTask
from raiden.transfer.views import list_channelstate_for_tokennetwork


def test_list_channelstate_for_tokennetwork(
        chain_state,
        token_network_state,
        payment_network_id,
        token_id,
):
    """Regression test for https://github.com/raiden-network/raiden/issues/3257"""
    token_address = token_id
    result = list_channelstate_for_tokennetwork(
        chain_state=chain_state,
        payment_network_id=payment_network_id,
        token_address=token_address,
    )
    assert isinstance(result, list)


def test_initiator_task_view():
    """Test transfer_tasks_view(), which is used to generate the output of the
    pending transfers API, with an initiator task.
    """
    channel_id = factories.UNIT_CHANNEL_ID
    secret = factories.make_secret()
    transfer = factories.create(factories.LockedTransferProperties(secret=secret))
    secrethash = transfer.lock.secrethash
    transfer_description = TransferDescriptionWithSecretState(
        secret=secret,
        amount=transfer.balance_proof.locked_amount,
        payment_identifier=transfer.payment_identifier,
        initiator=transfer.initiator,
        target=transfer.target,
        payment_network_identifier=factories.UNIT_PAYMENT_NETWORK_IDENTIFIER,
        token_network_identifier=factories.UNIT_TOKEN_NETWORK_ADDRESS,
    )
    transfer_state = InitiatorTransferState(
        transfer_description=transfer_description,
        channel_identifier=channel_id,
        transfer=transfer,
        revealsecret=None,
    )
    payment_state = InitiatorPaymentState({secrethash: transfer_state})
    task = InitiatorTask(
        token_network_identifier=factories.UNIT_TOKEN_NETWORK_ADDRESS,
        manager_state=payment_state,
    )
    payment_mapping = {secrethash: task}

    view = transfer_tasks_view(payment_mapping)

    assert len(view) == 1
    pending_transfer = view[0]
    assert pending_transfer.get('role') == 'initiator'
    balance_proof = transfer.balance_proof
    assert pending_transfer.get('channel_identifier') == str(balance_proof.channel_identifier)
    assert pending_transfer.get('locked_amount') == str(balance_proof.locked_amount)
    assert pending_transfer.get('transferred_amount') == str(balance_proof.transferred_amount)


def test_mediator_task_view():
    """Same as above for mediator tasks."""
    secret1 = factories.make_secret(1)
    locked_amount1 = 11
    payee_transfer = factories.create(factories.LockedTransferProperties(secret=secret1))
    payer_transfer = factories.create(factories.LockedTransferSignedStateProperties(
        transfer=factories.LockedTransferProperties(
            secret=secret1,
            payment_identifier=1,
            balance_proof=factories.BalanceProofProperties(
                locked_amount=locked_amount1,
            ),
        ),
    ))
    secrethash1 = payee_transfer.lock.secrethash
    initiator = payee_transfer.initiator
    initiator_channel = factories.create(factories.NettingChannelStateProperties(
        partner_state=factories.NettingChannelEndStateProperties(address=initiator, balance=100),
    ))
    routes = [factories.route_from_channel(initiator_channel)]
    transfer_state1 = MediatorTransferState(secrethash=secrethash1, routes=routes)
    transfer_state1.transfers_pair.append(MediationPairState(
        payer_transfer=payer_transfer,
        payee_transfer=payee_transfer,
        payee_address=payee_transfer.target,
    ))
    task1 = MediatorTask(
        token_network_identifier=factories.UNIT_TOKEN_NETWORK_ADDRESS,
        mediator_state=transfer_state1,
    )

    secret2 = factories.make_secret(2)
    locked_amount2 = 13
    transfer2 = factories.create(factories.LockedTransferSignedStateProperties(
        transfer=factories.LockedTransferProperties(
            secret=secret2,
            payment_identifier=2,
            balance_proof=factories.BalanceProofProperties(
                locked_amount=locked_amount2,
            ),
        ),
    ))
    secrethash2 = transfer2.lock.secrethash
    transfer_state2 = MediatorTransferState(secrethash=secrethash2, routes=routes)
    transfer_state2.waiting_transfer = WaitingTransferState(transfer=transfer2)
    task2 = MediatorTask(
        token_network_identifier=factories.UNIT_TOKEN_NETWORK_ADDRESS,
        mediator_state=transfer_state2,
    )

    payment_mapping = {secrethash1: task1, secrethash2: task2}
    view = transfer_tasks_view(payment_mapping)

    assert len(view) == 2
    if view[0].get('payment_identifier') == '1':
        pending_transfer, waiting_transfer = view
    else:
        waiting_transfer, pending_transfer = view

    assert pending_transfer.get('role') == waiting_transfer.get('role') == 'mediator'
    assert pending_transfer.get('payment_identifier') == '1'
    assert waiting_transfer.get('payment_identifier') == '2'
    assert pending_transfer.get('locked_amount') == str(locked_amount1)
    assert waiting_transfer.get('locked_amount') == str(locked_amount2)


def test_target_task_view():
    """Same as above for target tasks."""
    secret = factories.make_secret()
    transfer = factories.create(factories.LockedTransferSignedStateProperties(
        transfer=factories.LockedTransferProperties(secret=secret),
    ))
    secrethash = transfer.lock.secrethash
    mediator = factories.make_address()
    mediator_channel = factories.create(factories.NettingChannelStateProperties(
        partner_state=factories.NettingChannelEndStateProperties(address=mediator, balance=100),
    ))
    transfer_state = TargetTransferState(route=None, transfer=transfer, secret=secret)
    task = TargetTask(
        token_network_identifier=factories.UNIT_TOKEN_NETWORK_ADDRESS,
        channel_identifier=mediator_channel.identifier,
        target_state=transfer_state,
    )
    payment_mapping = {secrethash: task}

    view = transfer_tasks_view(payment_mapping)

    assert len(view) == 1
    pending_transfer = view[0]
    assert pending_transfer.get('role') == 'target'
    assert pending_transfer.get('locked_amount') == str(transfer.balance_proof.locked_amount)
    assert pending_transfer.get('payment_identifier') == str(transfer.payment_identifier)
