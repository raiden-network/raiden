from collections import Counter
from copy import deepcopy
from random import Random

from hypothesis import assume, event
from hypothesis.stateful import (
    Bundle,
    RuleBasedStateMachine,
    initialize,
    invariant,
    precondition,
    rule,
)
from hypothesis.strategies import builds, composite, integers, random_module, randoms

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
from raiden.utils import random_secret, sha3


@composite
def secret(draw):
    return draw(builds(random_secret))


def event_types_match(events, *expected_types):
    return Counter([type(event) for event in events]) == Counter(expected_types)


class ChainStateStateMachine(RuleBasedStateMachine):

    def __init__(self, address=None, channels_with=None):
        self.address = address or factories.make_address()
        self.channels_with = channels_with or [factories.make_address()]
        self.replay_path = False
        self.channels = None
        super().__init__()

    @initialize(
        block_number=integers(min_value=GENESIS_BLOCK_NUMBER + 1),
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

        self.channels = list()

        for partner_address in self.channels_with:
            channel = factories.make_channel(
                our_balance=1000,
                partner_balance=1000,
                token_network_identifier=self.token_network_id,
                our_address=self.address,
                partner_address=partner_address,
            )
            channel_new_state_change = ContractReceiveChannelNew(
                factories.make_transaction_hash(),
                self.token_network_id,
                channel,
                self.block_number,
            )
            node.state_transition(self.chain_state, channel_new_state_change)

            self.channels.append(channel)

    def event(self, description):
        """ Wrapper for hypothesis' event function.

        hypothesis.event raises an exception when invoked outside of hypothesis
        context, so skip it when we are replaying a failed path.
        """
        if not self.replay_path:
            event(description)

    @precondition(lambda self: self.channels)
    @invariant()
    def channel_state_invariants(self):
        """ Check the invariants for the channel state given in the Raiden specification """

        for netting_channel in self.channels:
            our_state = netting_channel.our_state
            partner_state = netting_channel.partner_state

            our_transferred_amount = 0
            if our_state.balance_proof:
                our_transferred_amount = our_state.balance_proof.transferred_amount
                assert our_transferred_amount >= 0

            partner_transferred_amount = 0
            if partner_state.balance_proof:
                partner_transferred_amount = partner_state.balance_proof.transferred_amount
                assert partner_transferred_amount >= 0

            assert channel.get_distributable(our_state, partner_state) >= 0
            assert channel.get_distributable(partner_state, our_state) >= 0

            our_deposit = netting_channel.our_total_deposit
            partner_deposit = netting_channel.partner_total_deposit
            total_deposit = our_deposit + partner_deposit

            our_amount_locked = channel.get_amount_locked(our_state)
            our_balance = channel.get_balance(our_state, partner_state)
            partner_amount_locked = channel.get_amount_locked(partner_state)
            partner_balance = channel.get_balance(partner_state, our_state)

            # invariant (5.1R), add withdrawn amounts when implemented
            assert 0 <= our_amount_locked <= our_balance
            assert 0 <= partner_amount_locked <= partner_balance
            assert our_amount_locked <= total_deposit
            assert partner_amount_locked <= total_deposit

            our_transferred = partner_transferred_amount - our_transferred_amount
            netted_transferred = our_transferred + partner_amount_locked - our_amount_locked

            # invariant (6R), add withdrawn amounts when implemented
            assert 0 <= our_deposit + our_transferred - our_amount_locked <= total_deposit
            assert 0 <= partner_deposit - our_transferred - partner_amount_locked <= total_deposit

            # invariant (7R), add withdrawn amounts when implemented
            assert - our_deposit <= netted_transferred <= partner_deposit


class InitiatorState(ChainStateStateMachine):

    def __init__(self):
        super().__init__()
        self.used_secrets = set()
        self.processed_secret_requests = set()
        self.initiated = set()

    @property
    def channel(self):
        return self.channels[0]

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
        assume(secret not in self.used_secrets)
        self.used_secrets.add(secret)
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
        assume(transfer.secret not in self.initiated)
        assume(transfer.amount <= self._available_amount())
        action = self._action_init_initiator(transfer)
        result = node.state_transition(self.chain_state, action)
        assert event_types_match(result.events, SendLockedTransfer)
        self.initiated.add(transfer.secret)
        return action

    @rule(previous_action=init_initiators)
    def replay_init_initator(self, previous_action):
        result = node.state_transition(self.chain_state, previous_action)
        assert not result.events

    @rule(previous_action=init_initiators)
    def valid_secret_request(self, previous_action):
        action = self._receive_secret_request(previous_action.transfer)
        result = node.state_transition(self.chain_state, action)
        if action.secrethash in self.processed_secret_requests:
            assert not result.events
            self.event('Valid SecretRequest dropped due to previous invalid one.')
        else:
            assert event_types_match(result.events, SendSecretReveal)
            self.event('Valid SecretRequest accepted.')
            self.processed_secret_requests.add(action.secrethash)

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
        if action.secrethash not in self.processed_secret_requests:
            assert event_types_match(result.events, EventPaymentSentFailed)
        else:
            assert not result.events
        self.processed_secret_requests.add(action.secrethash)

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


def test_regression_malicious_secret_request_handled_properly():
    state = InitiatorState()
    state.replay_path = True

    state.initialize(block_number=1, random=Random(), random_seed=None)
    v1 = state.populate_transfer_descriptions(amount=1, payment_id=1, secret=b'\x00' * 32)
    v2 = state.valid_init_initiator(transfer=v1)
    v3 = state.wrong_amount_secret_request(amount=0, previous_action=v2)
    state.invalid_authentic_secret_request(v3)
    state.replay_init_initator(previous_action=v2)

    state.teardown()
