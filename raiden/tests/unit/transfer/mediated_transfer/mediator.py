# -*- coding: utf-8 -*-
from raiden.transfer.architecture import StateManager
from raiden.transfer.state import (
    RoutesState,
)
from raiden.transfer.mediated_transfer import mediator
from raiden.transfer.mediated_transfer.state import (
    MediatorState,
    LockedTransferState,
)
from raiden.transfer.mediated_transfer.state_change import (
    ActionInitMediator,
)
from raiden.transfer.mediated_transfer.events import (
    SendMediatedTransfer,
    SendRefundTransfer,
)
from . import factories


def make_init_statechange(from_transfer,
                          routes,
                          from_route,
                          our_address=factories.ADDR):

    block_number = 1
    init_state_change = ActionInitMediator(
        our_address,
        from_transfer,
        RoutesState(routes),
        from_route,
        block_number,
    )
    return init_state_change


def make_from(amount, target, from_expiration):
    from_route = factories.make_route(
        factories.HOP1,
        available_balance=amount,
    )

    identifier = 0
    from_transfer = LockedTransferState(
        identifier,
        amount,
        factories.UNIT_TOKEN_ADDRESS,
        target,
        from_expiration,
        hashlock=factories.UNIT_HASHLOCK,
        secret=None,
    )

    return from_route, from_transfer


def test_init_mediator():
    from_route, from_transfer = make_from(
        amount=factories.UNIT_TRANSFER_AMOUNT,
        target=factories.HOP2,
        from_expiration=factories.HOP1_TIMEOUT,
    )

    routes = [
        factories.make_route(factories.HOP2, available_balance=factories.UNIT_TRANSFER_AMOUNT),
    ]

    init_state_change = make_init_statechange(
        from_transfer,
        routes,
        from_route,
    )

    mediator_state_machine = StateManager(
        mediator.state_transition,
        None,
    )

    assert mediator_state_machine.current_state is None

    events = mediator_state_machine.dispatch(
        init_state_change,
    )

    mediator_state = mediator_state_machine.current_state
    assert isinstance(mediator_state, MediatorState)
    assert mediator_state.our_address == factories.ADDR
    assert mediator_state.block_number == init_state_change.block_number
    assert mediator_state.transfers_pair[0].payer_transfer == from_transfer
    assert mediator_state.transfers_pair[0].payer_route == from_route

    assert len(events), 'we have a valid route, the mediated transfer event must be emited'

    mediated_transfers = [
        e for e in events
        if isinstance(e, SendMediatedTransfer)
    ]
    assert len(mediated_transfers) == 1, 'mediated_transfer should /not/ split the transfer'
    mediated_transfer = mediated_transfers[0]

    assert mediated_transfer.token == from_transfer.token, 'transfer token address mismatch'
    assert mediated_transfer.amount == from_transfer.amount, 'transfer amount mismatch'
    assert mediated_transfer.expiration < from_transfer.expiration, 'transfer expiration mismatch'
    assert mediated_transfer.hashlock == from_transfer.hashlock, 'wrong hashlock'


def test_no_valid_routes():
    from_route, from_transfer = make_from(
        amount=factories.UNIT_TRANSFER_AMOUNT,
        target=factories.HOP2,
        from_expiration=factories.HOP1_TIMEOUT,
    )

    routes = [
        factories.make_route(factories.HOP2, available_balance=factories.UNIT_TRANSFER_AMOUNT - 1),
        factories.make_route(factories.HOP3, available_balance=1),
    ]

    init_state_change = make_init_statechange(
        from_transfer,
        routes,
        from_route,
    )

    mediator_state_machine = StateManager(
        mediator.state_transition,
        None,
    )

    assert mediator_state_machine.current_state is None

    events = mediator_state_machine.dispatch(
        init_state_change,
    )

    assert mediator_state_machine.current_state is None

    assert len(events) == 1
    assert isinstance(events[0], SendRefundTransfer)


def test_lock_timeout_lower_than_previous_channel_settlement_period():
    # For a path A-B-C, B cannot forward a mediated transfer to C with
    # a lock timeout larger than the settlement timeout of the A-B
    # channel.
    #
    # Consider that an attacker controls both nodes A and C:
    #
    # Channels A <-> B and B <-> C have a settlement=10 and B has a
    # reveal_timeout=5
    #
    # (block=1) A -> B [T1 expires=20]
    # (block=1) B -> C [T2 expires=20-5]
    # (block=1) A close channel A-B
    # (block=5) C close channel B-C (waited until lock_expiration=settle_timeout)
    # (block=11) A call settle on channel A-B (settle_timeout is over)
    # (block=12) C call unlock on channel B-C (lock is still valid)
    #
    # If B used min(lock.expiration, previous_channel.settlement)
    #
    # (block=1) A -> B [T1 expires=20]
    # (block=1) B -> C [T2 expires=min(20,10)-5]
    # (block=1) A close channel A-B
    # (block=4) C close channel B-C (waited all possible blocks)
    # (block=5) C call unlock on channel B-C (C is forced to unlock)
    # (block=6) B learns the secret
    # (block=7) B call unlock on channel A-B (settle_timeout is over)
    pass


def test_do_not_withdraw_an_almost_expiring_lock_if_a_payment_didnt_occur():
    # For a path A1-B-C-A2, an attacker controlling A1 and A2 should not be
    # able to force B-C to close the channel by burning token.
    #
    # The attack would be as follows:
    #
    # - Attacker uses two nodes to open two really cheap channels A1 <-> B and
    #   node A2 <-> C
    # - Attacker sends a mediated message with the lowest possible token
    #   amount from A1 through B and C to A2
    # - Since the attacker controls A1 and A2 it knows the secret, she can choose
    #   when the secret is revealed
    # - The secret is hold back until the hash time lock B->C is almost expiring,
    #   then it's revealed (meaning that the attacker is losing token, that's why
    #   it's using the lowest possible amount)
    # - C wants the token from B, it will reveal the secret and close the channel
    #   (because it must assume the balance proof won't make in time and it needs
    #   to unlock on-chain)
    #
    # Mitigation:
    #
    # - C should only close the channel B-C if he has paid A2, since this may
    #   only happen if the lock for the transfer C-A2 has not yet expired then C
    #   has enough time to follow the protocol without closing the channel B-C.
    pass


def mediate_transfer_payee_timeout_must_be_lower_than_settlement_and_payer_timeout():
    # Test:
    # - the current payer route/transfer is the reference, not the from_route / from_transfer
    # - the lowest value from blocks_until_settlement and lock expiration must be used
    pass


def payee_timeout_must_be_lower_than_payer_timeout_minus_reveal_timeout():
    # The payee could reveal the secret on it's lock expiration block, the
    # mediator node will respond with a balance-proof to the payee since the
    # lock is valid and the mediator can safely get the token from the payer,
    # the secret is know and if there are no additional blocks the mediator
    # will be at risk of not being able to withdraw on-chain, so the channel
    # will be closed to safely withdraw.
    #
    # T2.expiration cannot be equal to T1.expiration - reveal_timeout:
    #
    # T1 |---|
    # T2     |---|
    #        ^- reveal the secret
    #        T1.expiration - reveal_timeout == current_block -> withdraw on chain
    #
    # If T2.expiration canot be equal to T1.expiration - reveal_timeout minus ONE:
    #
    # T1 |---|
    # T2      |---|
    #         ^- reveal the secret
    #
    # Race:
    #  1> Secret is learned
    #  2> balance-proof is sent to payee (payee transfer is payed)
    #  3! New block is mined and Raiden learns about it
    #  4> Now the secret is know, the payee is payed, and the current block is
    #     equal to the payer.expiration - reveal-timeout -> withdraw on chain
    #
    # The race is depending on the handling of 3 before 4.
    #
    pass
