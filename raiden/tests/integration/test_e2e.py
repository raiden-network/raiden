# -*- coding: utf-8 -*-
import pytest
import gevent

from raiden.tests.utils.events import must_contain_entry
from raiden.tests.utils.log import get_all_state_events
from raiden.tests.utils.blockchain import wait_until_block
from raiden.transfer.mediated_transfer.events import EventWithdrawSuccess
from raiden.messages import MediatedTransfer


def mediated_transfer_almost_equal(first, second):
    assert first.identifier == second.identifier, "identifier doesn't match"
    assert first.token == second.token, "token address doesn't match"
    assert first.lock.amount == second.lock.amount, "lock amount doesn't match"
    assert first.lock.hashlock == second.lock.hashlock, "lock hashlock doesn't match"
    assert first.target == second.target, "target doesn't match"
    assert first.initiator == second.initiator, "initiator doesn't match"


def assert_path_mediated_transfer(*transfers):
    assert all(
        isinstance(t, MediatedTransfer)
        for t in transfers
    ), 'all transfers must be of type MediatedTransfer'

    for first, second in zip(transfers[:-1], transfers[1:]):
        mediated_transfer_almost_equal(first, second)

        assert first.recipient == second.sender, 'transfers are out-of-order'
        assert first.lock.expiration > second.lock.expiration, 'lock expiration is not decreasing'


@pytest.mark.parametrize('channels_per_node', [1])
@pytest.mark.parametrize('number_of_nodes', [3])
@pytest.mark.parametrize('settle_timeout', [50])
def test_mediation(raiden_network, token_addresses, settle_timeout):
    # The network has the following topology:
    #
    # App1 <--> App0 <--> App2

    token_address = token_addresses[0]
    app0, app1, app2 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

    identifier = 1
    amount = 1
    async_result = app1.raiden.mediated_transfer_async(
        token_address,
        amount,
        app2.raiden.address,
        identifier,
    )
    assert async_result.wait()

    mediator_chain = app0.raiden.chain
    settle_expiration = mediator_chain.block_number() + settle_timeout + 1
    wait_until_block(mediator_chain, settle_expiration)

    # context switch needed for tester to process the EventWithdrawSuccess
    gevent.sleep(1)

    app0_events = [
        event.event_object
        for event in get_all_state_events(app0.raiden.transaction_log)
    ]
    assert must_contain_entry(app0_events, EventWithdrawSuccess, {})
