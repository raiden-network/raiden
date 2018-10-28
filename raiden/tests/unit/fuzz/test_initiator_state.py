from copy import deepcopy
from random import Random

import pytest
from hypothesis import assume
from hypothesis.stateful import Bundle, RuleBasedStateMachine, initialize, rule
from hypothesis.strategies import binary, composite, integers, random_module, randoms

from raiden.constants import GENESIS_BLOCK_NUMBER
from raiden.tests.utils import factories
from raiden.transfer import channel, node
from raiden.transfer.events import EventPaymentSentFailed
from raiden.transfer.mediated_transfer.events import SendLockedTransfer, SendSecretReveal
from raiden.transfer.mediated_transfer.state_change import (
    ActionInitInitiator,
    ReceiveSecretRequest,
    TransferDescriptionWithSecretState,
)
from raiden.transfer.state import ChainState, PaymentNetworkState, TokenNetworkState
from raiden.transfer.state_change import ContractReceiveChannelNew
from raiden.utils import sha3


@composite
def secret(draw):
    return draw(binary(min_size=32, max_size=32))


def events_include(events, type, number=1):
    return len([event for event in events if isinstance(event, type)]) == number


class ChainStateStateMachine(RuleBasedStateMachine):

    @initialize(
        block_number=integers(min_value=GENESIS_BLOCK_NUMBER),
        random=randoms(),
        random_seed=random_module(),
    )
    def initialize(self, block_number, random, random_seed):
        self.random_seed = random_seed

        self.block_number = block_number
        self.random = random
        self.private_key, self.address = factories.make_privkey_address()

        self.chain_state = ChainState(
            self.random,
            self.block_number,
            self.address,
            factories.UNIT_CHAIN_ID,
        )

        self.token_network_id = factories.make_address()
        self.token_id = factories.make_address()
        self.token_network_state = TokenNetworkState(self.token_network_id, self.token_id)

        self.payment_network_id = factories.make_payment_network_identifier()
        self.payment_network_state = PaymentNetworkState(
            self.payment_network_id,
            [self.token_network_state],
        )

        self.chain_state.identifiers_to_paymentnetworks[
            self.payment_network_id
        ] = self.payment_network_state

        self.channel = factories.make_channel(
            our_balance=1000,
            token_network_identifier=self.token_network_id,
        )

        channel_new_state_change = ContractReceiveChannelNew(
            factories.make_transaction_hash(),
            self.token_network_id,
            self.channel,
            self.block_number,
        )

        node.state_transition(self.chain_state, channel_new_state_change)


class InitiatorState(ChainStateStateMachine):

    def __init__(self):
        super().__init__()
        self.failed_secret_requests = set()
        self.initiated = set()

        self.failing_path_2 = False
        self.failing_path_4 = False

    def _action_init_initiator(self, transfer: TransferDescriptionWithSecretState):
        return ActionInitInitiator(
            transfer,
            [factories.route_from_channel(self.channel)],
        )

    def _receive_secret_request(self, transfer: TransferDescriptionWithSecretState):
        secrethash = sha3(transfer.secret)
        return ReceiveSecretRequest(
            payment_identifier=transfer.payment_identifier,
            amount=transfer.amount,
            expiration=self.block_number + 10,  # todo
            secrethash=secrethash,
            sender=transfer.target,
        )

    transfers = Bundle('transfers')
    init_initiators = Bundle('init_initiators')
    invalid_authentic_secret_requests = Bundle('invalid_authentic_secret_requests')
    unauthentic_secret_requests = Bundle('unauthentic_secret_requests')

    @rule(
        target=transfers,
        payment_id=integers(min_value=1),
        amount=integers(min_value=1, max_value=100),
        secret=secret(),
    )
    def populate_transfer_descriptions(self, payment_id, amount, secret):
        return TransferDescriptionWithSecretState(
            payment_network_identifier=self.payment_network_id,
            payment_identifier=payment_id,
            amount=amount,
            token_network_identifier=self.token_network_id,
            initiator=self.address,
            target=self.channel.partner_state.address,
            secret=secret,
        )

    def _secret_in_use(self, secret):
        return sha3(secret) in self.chain_state.payment_mapping.secrethashes_to_task

    def _available_amount(self):
        return channel.get_distributable(self.channel.our_state, self.channel.partner_state)

    @rule(target=init_initiators, transfer=transfers)
    def valid_init_initiator(self, transfer):
        if not self.failing_path_2:
            assume(transfer.payment_identifier not in self.initiated)
        assume(not self._secret_in_use(transfer.secret))
        assume(transfer.amount <= self._available_amount())
        action = self._action_init_initiator(transfer)
        result = node.state_transition(self.chain_state, action)
        assert events_include(result.events, SendLockedTransfer)
        self.initiated.add(transfer.payment_identifier)
        return action

    @rule(previous_action=init_initiators)
    def valid_secret_request(self, previous_action):
        if not self.failing_path_4:
            assume(previous_action.transfer.payment_identifier not in self.failed_secret_requests)
        action = self._receive_secret_request(previous_action.transfer)
        result = node.state_transition(self.chain_state, action)
        assert events_include(result.events, SendSecretReveal)

    @rule(
        target=invalid_authentic_secret_requests,
        previous_action=init_initiators,
        amount=integers(),
    )
    def wrong_amount_secret_request(self, previous_action, amount):
        assume(amount != previous_action.transfer.amount)
        transfer = deepcopy(previous_action.transfer)
        transfer.amount = amount
        return self._receive_secret_request(transfer)

    @rule(action=invalid_authentic_secret_requests)
    def invalid_authentic_secret_request(self, action):
        result = node.state_transition(self.chain_state, action)
        if action.payment_identifier not in self.failed_secret_requests:
            assert events_include(result.events, EventPaymentSentFailed)
        else:
            assert not result.events
        self.failed_secret_requests.add(action.payment_identifier)

    @rule(target=unauthentic_secret_requests, previous_action=init_initiators, secret=secret())
    def secret_request_with_wrong_secrethash(self, previous_action, secret):
        assume(sha3(secret) != sha3(previous_action.transfer.secret))
        transfer = deepcopy(previous_action.transfer)
        transfer.secret = secret
        return self._receive_secret_request(transfer)

    @rule(
        target=unauthentic_secret_requests,
        previous_action=init_initiators,
        payment_identifier=integers(),
    )
    def secret_request_with_wrong_payment_id(self, previous_action, payment_identifier):
        assume(payment_identifier != previous_action.transfer.payment_identifier)
        transfer = deepcopy(previous_action.transfer)
        transfer.payment_identifier = payment_identifier
        return self._receive_secret_request(transfer)

    @rule(action=unauthentic_secret_requests)
    def unauthentic_secret_request(self, action):
        result = node.state_transition(self.chain_state, action)
        assert not result.events


TestInitiator = InitiatorState.TestCase


@pytest.mark.skip('AssertionError in the tested code (lock is already registered)')
# The firing assertion is commented: "The caller must ensure the same lock is not being used
# twice." It still looks like something that could happen (A transfer initiation is retried
# directly after the first was answered with a secret request.)
def test_failing_path_2():
    state = InitiatorState()
    state.failing_path_2 = True
    state.initialize(block_number=1, random=Random(), random_seed=None)
    v1 = state.populate_transfer_descriptions(amount=1, payment_id=1, secret=b'\x00' * 32)
    v2 = state.valid_init_initiator(transfer=v1)
    v3 = state.wrong_amount_secret_request(amount=0, previous_action=v2)
    state.invalid_authentic_secret_request(v3)
    state.valid_init_initiator(transfer=v1)
    state.teardown()


@pytest.mark.skip('Previous invalid secret request keeps valid one from being processed')
# When processing the invalid secret request, the InitiatorTask is cleared from the dict
# in transfer/node.py:200, which results in the following valid secret request not being
# processed. Is this intentional?
def test_failing_path_4():
    state = InitiatorState()
    state.failing_path_4 = True
    state.initialize(block_number=1, random=Random(), random_seed=None)
    v1 = state.populate_transfer_descriptions(amount=1, payment_id=1, secret=b'\x00' * 32)
    v2 = state.valid_init_initiator(transfer=v1)
    v3 = state.wrong_amount_secret_request(amount=0, previous_action=v2)
    state.invalid_authentic_secret_request(action=v3)
    state.valid_secret_request(previous_action=v2)
    state.teardown()
