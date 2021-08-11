from collections import Counter, defaultdict
from dataclasses import dataclass, field, replace
from random import Random
from typing import Any, Dict, List, Set

import pytest
from hypothesis import assume, event
from hypothesis.stateful import (
    Bundle,
    RuleBasedStateMachine,
    consumes,
    initialize,
    invariant,
    multiple,
    rule,
)
from hypothesis.strategies import binary, builds, composite, integers, random_module, randoms

from raiden.constants import GENESIS_BLOCK_NUMBER, LOCKSROOT_OF_NO_LOCKS, UINT64_MAX
from raiden.settings import DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS, DEFAULT_WAIT_BEFORE_LOCK_REMOVAL
from raiden.tests.fuzz import utils
from raiden.tests.utils import factories
from raiden.tests.utils.factories import make_block_hash
from raiden.transfer import channel, node
from raiden.transfer.architecture import StateChange
from raiden.transfer.channel import compute_locksroot
from raiden.transfer.events import (
    EventInvalidReceivedLockedTransfer,
    EventPaymentReceivedSuccess,
    EventPaymentSentFailed,
    EventPaymentSentSuccess,
    SendProcessed,
)
from raiden.transfer.mediated_transfer.events import (
    EventUnlockClaimFailed,
    EventUnlockClaimSuccess,
    EventUnlockSuccess,
    SendLockedTransfer,
    SendSecretRequest,
    SendSecretReveal,
    SendUnlock,
)
from raiden.transfer.mediated_transfer.state import LockedTransferSignedState
from raiden.transfer.mediated_transfer.state_change import (
    ActionInitInitiator,
    ActionInitMediator,
    ReceiveSecretReveal,
    TransferDescriptionWithSecretState,
)
from raiden.transfer.state import (
    ChainState,
    ChannelState,
    HashTimeLockState,
    NettingChannelState,
    TokenNetworkRegistryState,
    TokenNetworkState,
    make_empty_pending_locks_state,
)
from raiden.transfer.state_change import (
    Block,
    ContractReceiveChannelNew,
    ContractReceiveChannelSettled,
)
from raiden.utils.copy import deepcopy
from raiden.utils.secrethash import sha256_secrethash
from raiden.utils.transfers import random_secret
from raiden.utils.typing import (
    Address,
    BlockExpiration,
    BlockGasLimit,
    BlockNumber,
    MessageID,
    Nonce,
    PrivateKey,
    Secret,
    SecretHash,
    TokenAddress,
    TokenAmount,
)


@composite
def secret(draw):
    return draw(builds(random_secret))


@composite
def address(draw):
    return draw(binary(min_size=20, max_size=20))


@composite
def payment_id(draw):
    return draw(integers(min_value=1, max_value=UINT64_MAX))


def event_types_match(events, *expected_types):
    return Counter([type(event) for event in events]) == Counter(expected_types)


def transferred_amount(state):
    return 0 if not state.balance_proof else state.balance_proof.transferred_amount


@dataclass
class Route:
    hops: List[Address]
    channel_from: int = 0

    @property
    def initiator(self):
        return self.hops[0]

    @property
    def target(self):
        return self.hops[-1]


# shared bundles of ChainStateStateMachine and all mixin classes
routes = Bundle("routes")
init_initiators = Bundle("init_initiators")
init_mediators = Bundle("init_mediators")
send_locked_transfers = Bundle("send_locked_transfers")
secret_requests = Bundle("secret_requests")
send_secret_requests = Bundle("send_secret_requests")
send_secret_reveals_backward = Bundle("send_secret_reveals_backward")
send_secret_reveals_forward = Bundle("send_secret_reveals_forward")
send_unlocks = Bundle("send_unlocks")

AddressToAmount = Dict[Address, TokenAmount]


def make_tokenamount_defaultdict():
    return defaultdict(lambda: TokenAmount(0))


@dataclass
class TransferOrder:
    initiated: List[SecretHash] = field(default_factory=list)
    answered: List[SecretHash] = field(default_factory=list)
    # TODO generalize this to channels with multiple routes


@dataclass
class Client:
    chain_state: ChainState

    address_to_channel: Dict[Address, NettingChannelState] = field(default_factory=dict)
    expected_expiry: Dict[SecretHash, BlockNumber] = field(default_factory=dict)
    our_previous_deposit: AddressToAmount = field(default_factory=make_tokenamount_defaultdict)
    partner_previous_deposit: AddressToAmount = field(default_factory=make_tokenamount_defaultdict)
    our_previous_transferred: AddressToAmount = field(default_factory=make_tokenamount_defaultdict)
    partner_previous_transferred: AddressToAmount = field(
        default_factory=make_tokenamount_defaultdict
    )
    our_previous_unclaimed: AddressToAmount = field(default_factory=make_tokenamount_defaultdict)
    partner_previous_unclaimed: AddressToAmount = field(
        default_factory=make_tokenamount_defaultdict
    )
    transfer_order: TransferOrder = field(default_factory=TransferOrder)

    def assert_monotonicity_invariants(self):
        """Assert all monotonicity properties stated in Raiden specification"""
        for (
            address,
            netting_channel,
        ) in self.address_to_channel.items():  # pylint: disable=no-member

            # constraint (1TN)
            assert netting_channel.our_total_deposit >= self.our_previous_deposit[address]
            assert netting_channel.partner_total_deposit >= self.partner_previous_deposit[address]
            self.our_previous_deposit[address] = netting_channel.our_total_deposit
            self.partner_previous_deposit[address] = netting_channel.partner_total_deposit

            # TODO add constraint (2TN) when withdrawal is implemented
            # constraint (3R) and (4R)
            our_transferred = transferred_amount(netting_channel.our_state)
            partner_transferred = transferred_amount(netting_channel.partner_state)
            our_unclaimed = channel.get_amount_unclaimed_onchain(netting_channel.our_state)
            partner_unclaimed = channel.get_amount_unclaimed_onchain(netting_channel.partner_state)
            assert our_transferred >= self.our_previous_transferred[address]
            assert partner_transferred >= self.partner_previous_transferred[address]
            assert (
                our_unclaimed + our_transferred
                >= self.our_previous_transferred[address] + self.our_previous_unclaimed[address]
            )
            assert (
                partner_unclaimed + partner_transferred
                >= self.partner_previous_transferred[address]
                + self.partner_previous_unclaimed[address]
            )
            self.our_previous_transferred[address] = our_transferred
            self.partner_previous_transferred[address] = partner_transferred
            self.our_previous_unclaimed[address] = our_unclaimed
            self.partner_previous_unclaimed[address] = partner_unclaimed

    def assert_channel_state_invariants(self):
        """Assert all channel state invariants given in the Raiden specification"""
        for netting_channel in self.address_to_channel.values():  # pylint: disable=no-member
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
            assert -our_deposit <= netted_transferred <= partner_deposit


class ChainStateStateMachine(RuleBasedStateMachine):
    def __init__(self):
        self.replay_path: bool = False
        self.address_to_privkey: Dict[Address, PrivateKey] = {}
        self.address_to_client: Dict[Address, Client] = {}
        self.transfer_order = TransferOrder()
        super().__init__()

    def new_address(self) -> Address:
        privkey, address = factories.make_privkey_address()
        self.address_to_privkey[address] = privkey
        return address

    def _new_channel_state(self, our_address, partner_address):
        identifier = factories.make_canonical_identifier(
            token_network_address=self.token_network_address
        )
        our_state = factories.NettingChannelEndStateProperties(
            balance=TokenAmount(1000), address=our_address
        )
        partner_state = factories.NettingChannelEndStateProperties(
            balance=TokenAmount(1000), address=partner_address
        )
        return factories.create(
            factories.NettingChannelStateProperties(
                our_state=our_state, partner_state=partner_state, canonical_identifier=identifier
            )
        )

    def new_channel(self, client_address: Address, partner_address: Address = None) -> Address:
        """Create a new partner address with private key and channel. The
        private key and channels are listed in the instance's dictionaries,
        the address is returned and should be added to the partners Bundle.
        """
        if not partner_address:
            partner_address = self.new_address()

        client = self.address_to_client[client_address]
        channel = self._new_channel_state(client_address, partner_address)
        client.address_to_channel[partner_address] = channel

        partner_client = self.address_to_client.get(partner_address)
        if partner_client is not None:
            mirrored = deepcopy(channel)
            mirrored.our_state, mirrored.partner_state = mirrored.partner_state, mirrored.our_state
            partner_client.address_to_channel[client_address] = mirrored

        return partner_address

    def _new_channel_transaction(self, client_address, partner_address):
        client = self.address_to_client[client_address]
        channel_state = client.address_to_channel[partner_address]
        assert isinstance(channel_state, NettingChannelState)
        channel_new_state_change = ContractReceiveChannelNew(
            transaction_hash=factories.make_transaction_hash(),
            channel_state=channel_state,
            block_number=self.block_number,
            block_hash=factories.make_block_hash(),
        )
        node.state_transition(client.chain_state, channel_new_state_change)

    def new_channel_with_transaction(
        self, client_address: Address, partner_address: Address = None
    ) -> Address:
        partner_address = self.new_channel(client_address, partner_address)
        self._new_channel_transaction(client_address, partner_address)
        if partner_address in self.address_to_client:
            self._new_channel_transaction(partner_address, client_address)
        return partner_address

    def new_client(self) -> Address:
        address = self.new_address()

        chain_state = ChainState(
            pseudo_random_generator=self.random,
            block_number=self.block_number,
            block_hash=self.block_hash,
            our_address=address,
            chain_id=factories.UNIT_CHAIN_ID,
        )
        chain_state.identifiers_to_tokennetworkregistries[
            self.token_network_registry_address
        ] = deepcopy(self.token_network_registry_state)

        chain_state.tokennetworkaddresses_to_tokennetworkregistryaddresses[
            self.token_network_address
        ] = self.token_network_registry_address

        self.address_to_client[address] = Client(chain_state=chain_state)

        return address

    @initialize(
        target=routes,
        block_number=integers(min_value=GENESIS_BLOCK_NUMBER + 1),
        random=randoms(),
        random_seed=random_module(),
    )
    def initialize_all(self, block_number, random, random_seed):
        self.random_seed = random_seed

        self.block_number = block_number
        self.block_hash = factories.make_block_hash()
        self.random = random

        self.token_network_address = factories.UNIT_TOKEN_NETWORK_ADDRESS
        self.token_id = factories.UNIT_TOKEN_ADDRESS
        self.token_network_state = TokenNetworkState(
            address=self.token_network_address,
            token_address=self.token_id,
        )

        self.token_network_registry_address = factories.make_token_network_registry_address()
        self.token_network_registry_state = TokenNetworkRegistryState(
            self.token_network_registry_address, [self.token_network_state]
        )

        return multiple(*self.create_network())

    def event(self, description):
        """Wrapper for hypothesis' event function.

        hypothesis.event raises an exception when invoked outside of hypothesis
        context, so skip it when we are replaying a failed path.
        """
        if not self.replay_path:
            event(description)

    @invariant()
    def chain_state_invariants(self):
        for client in self.address_to_client.values():
            client.assert_monotonicity_invariants()
            client.assert_channel_state_invariants()

    def channel_opened(self, partner_address, client_address):
        try:
            client = self.address_to_client[client_address]
        except KeyError:
            return False
        else:
            needed_channel = client.address_to_channel[partner_address]
            return channel.get_status(needed_channel) == ChannelState.STATE_OPENED

    def create_network(self):
        raise NotImplementedError("Every fuzz test needs to override this.")


class InitiatorMixin:
    address_to_client: dict
    block_number: BlockNumber

    def __init__(self):
        super().__init__()
        self.used_secrets: Set[Secret] = set()
        self.processed_secret_request_secrethashes: Set[SecretHash] = set()
        self.initiated: Set[Secret] = set()

    def _available_amount(self, route):
        client = self.address_to_client[route.initiator]
        netting_channel = client.address_to_channel[route.hops[1]]
        return channel.get_distributable(netting_channel.our_state, netting_channel.partner_state)

    def _is_expired(self, secrethash, initiator):
        expiry = self.address_to_client[initiator].expected_expiry[secrethash]
        return self.block_number >= expiry + DEFAULT_WAIT_BEFORE_LOCK_REMOVAL

    def _is_removed(self, action):
        return self._is_expired(action.transfer.secrethash, action.transfer.initiator)

    def _action_init_initiator(self, route: Route, transfer: TransferDescriptionWithSecretState):
        client = self.address_to_client[route.initiator]
        channel = client.address_to_channel[route.hops[1]]
        if transfer.secrethash not in client.expected_expiry:
            client.expected_expiry[transfer.secrethash] = self.block_number + 10
        return ActionInitInitiator(transfer, [factories.make_route_from_channel(channel)])

    def _new_transfer_description(self, route, payment_id, amount, secret):
        self.used_secrets.add(secret)

        return TransferDescriptionWithSecretState(
            token_network_registry_address=self.token_network_registry_address,
            payment_identifier=payment_id,
            amount=amount,
            token_network_address=self.token_network_address,
            initiator=route.initiator,
            target=route.target,
            secret=secret,
        )

    @rule(
        target=send_locked_transfers,
        route=routes,
        payment_id=payment_id(),  # pylint: disable=no-value-for-parameter
        amount=integers(min_value=1, max_value=100),
        secret=secret(),  # pylint: disable=no-value-for-parameter
    )
    def valid_init_initiator(self, route, payment_id, amount, secret):
        assume(amount <= self._available_amount(route))
        assume(secret not in self.used_secrets)

        transfer = self._new_transfer_description(route, payment_id, amount, secret)
        action = self._action_init_initiator(route, transfer)
        client = self.address_to_client[route.initiator]
        result = node.state_transition(client.chain_state, action)

        assert event_types_match(result.events, SendLockedTransfer)

        self.initiated.add(transfer.secret)
        client.expected_expiry[transfer.secrethash] = self.block_number + 10
        self.transfer_order.initiated.append(secret)

        return utils.SendLockedTransferInNode(
            event=result.events[0],
            action=action,
            node=route.initiator,
            private_key=self.address_to_privkey[route.initiator],
        )

    @rule(
        route=routes,
        payment_id=payment_id(),  # pylint: disable=no-value-for-parameter
        excess_amount=integers(min_value=1),
        secret=secret(),  # pylint: disable=no-value-for-parameter
    )
    def exceeded_capacity_init_initiator(self, route, payment_id, excess_amount, secret):
        amount = self._available_amount(route) + excess_amount
        transfer = self._new_transfer_description(route, payment_id, amount, secret)
        action = self._action_init_initiator(route, transfer)
        client = self.address_to_client[route.initiator]
        result = node.state_transition(client.chain_state, action)
        assert event_types_match(result.events, EventPaymentSentFailed)
        self.event("ActionInitInitiator failed: Amount exceeded")

    @rule(
        previous=send_locked_transfers,
        route=routes,
        payment_id=payment_id(),  # pylint: disable=no-value-for-parameter
        amount=integers(min_value=1),
    )
    def used_secret_init_initiator(self, previous, route, payment_id, amount):
        assume(not self._is_removed(previous.action))

        client = self.address_to_client[previous.node]
        secret = previous.action.transfer.secret

        transfer = self._new_transfer_description(route, payment_id, amount, secret)
        action = self._action_init_initiator(route, transfer)
        result = node.state_transition(client.chain_state, action)

        assert not result.events
        self.event("ActionInitInitiator failed: Secret already in use.")

    @rule(previous=send_locked_transfers)
    def replay_init_initiator(self, previous):
        assume(not self._is_removed(previous.action))

        client = self.address_to_client[previous.node]
        result = node.state_transition(client.chain_state, previous.action)

        assert not result.events
        self.event("Replayed init_initiator action ignored")

    @rule(target=send_secret_reveals_forward, source=consumes(send_secret_requests))
    def process_valid_secret_request(
        self, source: utils.SendSecretRequestInNode
    ) -> utils.SendSecretRevealInNode:
        initiator_address = source.event.recipient
        initiator_client = self.address_to_client[initiator_address]

        state_change = utils.send_secret_request_to_receive_secret_request(source)
        assume(state_change.secrethash not in self.processed_secret_request_secrethashes)
        result = node.state_transition(initiator_client.chain_state, state_change)

        if state_change.secrethash in self.processed_secret_request_secrethashes:
            assert not result.events
            self.event("Valid SecretRequest dropped due to previous one with same secrethash.")
            return multiple()
        elif self._is_expired(state_change.secrethash, initiator_address):
            assert not result.events
            self.event("Otherwise valid SecretRequest dropped due to expired lock.")
            return multiple()
        else:
            assert event_types_match(result.events, SendSecretReveal)
            self.event("Valid SecretRequest accepted.")
            self.processed_secret_request_secrethashes.add(state_change.secrethash)
            return utils.SendSecretRevealInNode(node=initiator_address, event=result.events[0])

    @rule(source=send_secret_requests, wrong_amount=integers())
    def process_secret_request_with_wrong_amount(
        self, source: utils.SendSecretRequestInNode, wrong_amount
    ):
        initiator_address = source.event.recipient
        initiator_client = self.address_to_client[initiator_address]

        state_change = utils.send_secret_request_to_receive_secret_request(source)
        assume(wrong_amount != state_change.amount)
        state_change = replace(state_change, amount=wrong_amount)

        result = node.state_transition(initiator_client.chain_state, state_change)

        transfer_expired = self._is_expired(state_change.secrethash, initiator_address)
        secrethash_known = state_change.secrethash in self.processed_secret_request_secrethashes
        if transfer_expired or secrethash_known:
            assert not result.events
            self.event("Invalid secret request dropped silently (wrong amount)")
        else:
            self.processed_secret_request_secrethashes.add(state_change.secrethash)

    @rule(source=send_secret_requests, wrong_secret=secret())
    def process_secret_request_with_wrong_secrethash(
        self, source: utils.SendSecretRequestInNode, wrong_secret
    ):
        initiator_address = source.event.recipient
        initiator_client = self.address_to_client[initiator_address]

        state_change = utils.send_secret_request_to_receive_secret_request(source)
        wrong_secrethash = sha256_secrethash(wrong_secret)
        assume(wrong_secrethash != state_change.secrethash)
        state_change = replace(state_change, secrethash=wrong_secrethash)

        result = node.state_transition(initiator_client.chain_state, state_change)
        assert not result.events
        self.event("Invalid secret request dropped (wrong secrethash)")

    @rule(source=send_secret_requests, wrong_payment_identifier=integers())
    def process_secret_request_with_wrong_payment_identifier(
        self, source: utils.SendSecretRequestInNode, wrong_payment_identifier
    ):
        initiator_address = source.event.recipient
        initiator_client = self.address_to_client[initiator_address]

        state_change = utils.send_secret_request_to_receive_secret_request(source)
        assume(wrong_payment_identifier != state_change.payment_identifier)
        state_change = replace(state_change, payment_identifier=wrong_payment_identifier)

        result = node.state_transition(initiator_client.chain_state, state_change)
        assert not result.events
        self.event("Invalid secret request dropped (wrong payment identifier)")

    @rule(target=send_unlocks, source=consumes(send_secret_reveals_backward))
    def process_secret_reveal_as_initiator(
        self, source: utils.SendSecretRevealInNode
    ) -> utils.SendUnlockInNode:
        initiator_address = source.event.recipient
        private_key = self.address_to_privkey[initiator_address]
        initiator_client = self.address_to_client[initiator_address]

        state_change = utils.send_secret_reveal_to_recieve_secret_reveal(source)
        result = node.state_transition(initiator_client.chain_state, state_change)

        assert event_types_match(
            result.events, SendUnlock, EventPaymentSentSuccess, EventUnlockSuccess
        )
        self.event("Valid secret reveal processed in initiator node.")

        return utils.SendUnlockInNode(
            node=initiator_address, private_key=private_key, event=result.events[0]
        )

    @rule(source=send_secret_reveals_backward, wrong_secret=secret())
    def process_secret_reveal_with_mismatched_secret_as_initiator(
        self, source: utils.SendSecretRevealInNode, wrong_secret: Secret
    ):
        initiator_address = source.event.recipient
        initiator_client = self.address_to_client[initiator_address]

        state_change = utils.send_secret_reveal_to_recieve_secret_reveal(source)
        assume(state_change.secret != wrong_secret)
        state_change = replace(state_change, secret=wrong_secret)
        result = node.state_transition(initiator_client.chain_state, state_change)

        assert not result.events
        self.event("Secret reveal with wrong secret dropped in initiator node.")

    @rule(source=send_secret_reveals_backward, wrong_secret=secret())
    def process_secret_reveal_with_unknown_secrethash_as_initiator(
        self, source: utils.SendSecretRevealInNode, wrong_secret: Secret
    ):
        initiator_address = source.event.recipient
        initiator_client = self.address_to_client[initiator_address]

        state_change = utils.send_secret_reveal_to_recieve_secret_reveal(source)
        assume(state_change.secret != wrong_secret)
        wrong_secrethash = sha256_secrethash(wrong_secret)
        state_change = replace(state_change, secret=wrong_secret, secrethash=wrong_secrethash)
        result = node.state_transition(initiator_client.chain_state, state_change)

        assert not result.events
        self.event("Secret reveal with unknown secrethash dropped in initiator node.")

    @rule(source=send_secret_reveals_backward, wrong_channel_id=integers())
    def process_secret_reveal_with_wrong_channel_identifier_as_initiator(
        self, source: utils.SendSecretRevealInNode, wrong_channel_id
    ):
        initiator_address = source.event.recipient
        initiator_client = self.address_to_client[initiator_address]

        state_change = utils.send_secret_reveal_to_recieve_secret_reveal(source)
        assume(state_change.canonical_id.channel_id != wrong_channel_id)
        wrong_canonical_id = replace(state_change.canonical_id, channel_id=wrong_channel_id)
        state_change = replace(state_change, canonical_id=wrong_canonical_id)
        result = node.state_transition(initiator_client.chain_state, state_change)

        assert not result.events
        self.event("Secret reveal with unknown channel id dropped in initiator node.")

    @rule(
        source=send_secret_reveals_backward, wrong_channel_id=integers(), wrong_recipient=address()
    )
    def process_secret_reveal_with_wrong_queue_identifier_as_initiator(
        self, source: utils.SendSecretRevealInNode, wrong_channel_id, wrong_recipient
    ):
        initiator_address = source.event.recipient
        initiator_client = self.address_to_client[initiator_address]

        state_change = utils.send_secret_reveal_to_recieve_secret_reveal(source)
        assume(state_change.canonical_id.channel_id != wrong_channel_id)
        wrong_canonical_id = replace(
            state_change.queue_id.canonical_id, channel_id=wrong_channel_id
        )
        wrong_queue_id = replace(
            state_change.queue_id, canonical_id=wrong_canonical_id, recipient=wrong_recipient
        )
        state_change = replace(state_change, queue_id=wrong_queue_id)
        result = node.state_transition(initiator_client.chain_state, state_change)

        assert not result.events
        self.event("Secret reveal with unknown queue id dropped in initiator node.")


class TargetMixin:
    @rule(target=send_secret_requests, source=consumes(send_locked_transfers))
    def process_send_locked_transfer(
        self, source: utils.SendLockedTransferInNode
    ) -> utils.SendSecretRequestInNode:
        target_address = source.event.recipient
        target_client = self.address_to_client[target_address]

        if not self.replay_path:
            assume(source.action.transfer.secrethash == self.transfer_order.initiated[0])

        message = utils.send_lockedtransfer_to_locked_transfer(source)
        action = utils.locked_transfer_to_action_init_target(message)

        result = node.state_transition(target_client.chain_state, action)

        assert event_types_match(result.events, SendProcessed, SendSecretRequest)

        self.transfer_order.answered.append(self.transfer_order.initiated.pop(0))

        return utils.SendSecretRequestInNode(result.events[1], target_address)

    @rule(source=send_locked_transfers, scrambling=utils.balance_proof_scrambling())
    def process_send_locked_transfer_with_scrambled_balance_proof(
        self, source: utils.SendLockedTransferInNode, scrambling: Dict[str, Any]
    ):
        target_address = source.event.recipient
        target_client = self.address_to_client[target_address]

        scrambled_balance_proof = replace(source.event.balance_proof, **scrambling.kwargs)
        assume(scrambled_balance_proof != source.event.balance_proof)
        scrambled_transfer = replace(source.event.transfer, balance_proof=scrambled_balance_proof)
        scrambled_event = replace(source.event, transfer=scrambled_transfer)
        scrambled_source = replace(source, event=scrambled_event)

        message = utils.send_lockedtransfer_to_locked_transfer(scrambled_source)
        action = utils.locked_transfer_to_action_init_target(message)
        result = node.state_transition(target_client.chain_state, action)

        if scrambling.field == "canonical_identifier":
            assert not result.events
            self.event("SendLockedTransfer with wrong channel identifier dropped in target node.")
        else:
            assert event_types_match(
                result.events, EventInvalidReceivedLockedTransfer, EventUnlockClaimFailed
            )
            self.event("SendLockedTransfer with scrambled balance proof caught in target node.")

    @rule(source=send_locked_transfers, scrambling=utils.hash_time_lock_scrambling())
    def process_send_locked_transfer_with_scrambled_hash_time_lock_state(
        self, source: utils.SendLockedTransferInNode, scrambling: utils.Scrambling
    ):
        target_address = source.event.recipient
        target_client = self.address_to_client[target_address]

        scrambled_lock = replace(source.event.transfer.lock, **scrambling.kwargs)
        assume(scrambled_lock != source.event.transfer.lock)
        scrambled_transfer = replace(source.event.transfer, lock=scrambled_lock)
        scrambled_event = replace(source.event, transfer=scrambled_transfer)
        scrambled_source = replace(source, event=scrambled_event)

        message = utils.send_lockedtransfer_to_locked_transfer(scrambled_source)
        action = utils.locked_transfer_to_action_init_target(message)
        result = node.state_transition(target_client.chain_state, action)

        assert event_types_match(
            result.events, EventInvalidReceivedLockedTransfer, EventUnlockClaimFailed
        )
        self.event("SendLockedTransfer with scrambled lock caught in target node.")

    @rule(source=send_locked_transfers, scrambling=utils.locked_transfer_scrambling())
    def process_send_locked_transfer_with_scrambled_locked_transfer_parameter(
        self, source: utils.SendLockedTransferInNode, scrambling: utils.Scrambling
    ):
        target_address = source.event.recipient
        target_client = self.address_to_client[target_address]

        message = utils.send_lockedtransfer_to_locked_transfer(source)
        scrambled_message = replace(message, **scrambling.kwargs)
        assume(scrambled_message != message)
        action = utils.locked_transfer_to_action_init_target(scrambled_message)
        result = node.state_transition(target_client.chain_state, action)

        if scrambling.field in ("token_network_address", "channel_identifier"):
            assert not result.events
            self.event("SendLockedTransfer with token network or channel dropped.")
        else:
            assert event_types_match(
                result.events, EventInvalidReceivedLockedTransfer, EventUnlockClaimFailed
            )
            self.event("SendLockedTransfer with scrambled parameter caught in target node.")

    @rule(target=send_secret_reveals_backward, source=consumes(send_secret_reveals_forward))
    def process_secret_reveal_as_target(
        self, source: utils.SendSecretRevealInNode
    ) -> utils.SendSecretRevealInNode:
        state_change = utils.send_secret_reveal_to_recieve_secret_reveal(source)
        target_address = source.event.recipient
        target_client = self.address_to_client[target_address]

        result = node.state_transition(target_client.chain_state, state_change)
        assert event_types_match(result.events, SendSecretReveal)
        self.event("Valid SecretReveal processed in target node.")

        return utils.SendSecretRevealInNode(node=target_address, event=result.events[0])

    @rule(source=send_secret_reveals_forward, wrong_secret=secret())
    def process_secret_reveal_with_mismatched_secret_as_target(
        self, source: utils.SendSecretRevealInNode, wrong_secret: Secret
    ):
        state_change = utils.send_secret_reveal_to_recieve_secret_reveal(source)
        assume(state_change.secret != wrong_secret)
        state_change = replace(state_change, secret=wrong_secret)

        target_address = source.event.recipient
        target_client = self.address_to_client[target_address]
        result = node.state_transition(target_client.chain_state, state_change)
        assert not result.events
        self.event("SecretReveal with wrong secret dropped in target node.")

    @rule(source=send_secret_reveals_forward, wrong_secret=secret())
    def process_secret_reveal_with_unknown_secrethash_as_target(
        self, source: utils.SendSecretRevealInNode, wrong_secret: Secret
    ):
        state_change = utils.send_secret_reveal_to_recieve_secret_reveal(source)
        assume(state_change.secret != wrong_secret)
        wrong_secrethash = sha256_secrethash(wrong_secret)
        state_change = replace(state_change, secret=wrong_secret, secrethash=wrong_secrethash)

        target_address = source.event.recipient
        target_client = self.address_to_client[target_address]
        result = node.state_transition(target_client.chain_state, state_change)
        assert not result.events
        self.event("SecretReveal with unknown SecretHash dropped in target node.")

    @rule(source=send_secret_reveals_forward, wrong_channel_id=integers())
    def process_secret_reveal_with_wrong_channel_identifier_as_target(
        self, source: utils.SendSecretRevealInNode, wrong_channel_id
    ):
        state_change = utils.send_secret_reveal_to_recieve_secret_reveal(source)
        assume(state_change.canonical_id.channel_id != wrong_channel_id)
        wrong_canonical_id = replace(state_change.canonical_id, channel_id=wrong_channel_id)
        state_change = replace(state_change, canonical_id=wrong_canonical_id)

        target_address = source.event.recipient
        target_client = self.address_to_client[target_address]
        result = node.state_transition(target_client.chain_state, state_change)
        assert not result.events
        self.event("SecretReveal with unknown channel id dropped in target node.")

    @rule(
        source=send_secret_reveals_forward, wrong_channel_id=integers(), wrong_recipient=address()
    )
    def process_secret_reveal_with_wrong_queue_identifier_as_target(
        self, source: utils.SendSecretRevealInNode, wrong_channel_id, wrong_recipient
    ):
        state_change = utils.send_secret_reveal_to_recieve_secret_reveal(source)
        assume(state_change.canonical_id.channel_id != wrong_channel_id)
        wrong_canonical_id = replace(
            state_change.queue_id.canonical_id, channel_id=wrong_channel_id
        )
        wrong_queue_id = replace(
            state_change.queue_id, canonical_id=wrong_canonical_id, recipient=wrong_recipient
        )
        state_change = replace(state_change, queue_id=wrong_queue_id, recipient=wrong_recipient)

        target_address = source.event.recipient
        target_client = self.address_to_client[target_address]
        result = node.state_transition(target_client.chain_state, state_change)
        assert not result.events
        self.event("SecretReveal with unknown queue id dropped in target node.")

    @rule(source=consumes(send_unlocks))
    def process_unlock(self, source: utils.SendUnlockInNode):
        target_address = source.event.recipient
        target_client = self.address_to_client[target_address]

        assume(source.event.secrethash == self.transfer_order.answered[0])

        initiator_client = self.address_to_client[source.node]
        channel = initiator_client.address_to_channel[target_address]

        state_change = utils.send_unlock_to_receive_unlock(source, channel.canonical_identifier)
        result = node.state_transition(target_client.chain_state, state_change)

        assert event_types_match(
            result.events,
            SendProcessed,
            EventPaymentReceivedSuccess,
            EventUnlockClaimSuccess,
            SendProcessed,
        )
        self.event("Valid unlock processed in target node.")

        self.transfer_order.answered.pop(0)

    @rule(source=send_unlocks, wrong_secret=secret())
    def process_unlock_with_mismatched_secret(
        self, source: utils.SendUnlockInNode, wrong_secret: Secret
    ):
        target_address = source.event.recipient
        target_client = self.address_to_client[target_address]
        initiator_client = self.address_to_client[source.node]
        channel = initiator_client.address_to_channel[target_address]

        state_change = utils.send_unlock_to_receive_unlock(source, channel.canonical_identifier)
        assume(state_change.secret != wrong_secret)
        state_change = replace(state_change, secret=wrong_secret)

        result = node.state_transition(target_client.chain_state, state_change)
        assert not result.events
        self.event("Unlock with mismatched secret dropped in target node.")

    @rule(source=send_unlocks, wrong_secret=secret())
    def process_unlock_with_unknown_secrethash(
        self, source: utils.SendUnlockInNode, wrong_secret: Secret
    ):
        target_address = source.event.recipient
        target_client = self.address_to_client[target_address]
        initiator_client = self.address_to_client[source.node]
        channel = initiator_client.address_to_channel[target_address]

        state_change = utils.send_unlock_to_receive_unlock(source, channel.canonical_identifier)
        assume(state_change.secret != wrong_secret)
        wrong_secrethash = sha256_secrethash(wrong_secret)
        state_change = replace(state_change, secret=wrong_secret, secrethash=wrong_secrethash)

        result = node.state_transition(target_client.chain_state, state_change)
        assert not result.events
        self.event("Unlock with unknown SecretHash dropped in target node.")

    @rule(source=send_unlocks, scrambling=utils.balance_proof_scrambling())
    def process_unlock_with_scrambled_balance_proof(
        self, source: utils.SendUnlockInNode, scrambling: utils.Scrambling
    ):
        target_address = source.event.recipient
        target_client = self.address_to_client[target_address]
        initiator_client = self.address_to_client[source.node]
        channel = initiator_client.address_to_channel[target_address]

        state_change = utils.send_unlock_to_receive_unlock(source, channel.canonical_identifier)
        scrambled_balance_proof = replace(state_change.balance_proof, **scrambling.kwargs)
        assume(scrambled_balance_proof != state_change.balance_proof)
        scrambled_state_change = replace(state_change, balance_proof=scrambled_balance_proof)

        result = node.state_transition(target_client.chain_state, scrambled_state_change)
        assert not result.events
        self.event("Unlock with scrambled balance proof dropped in target node.")


class BalanceProofData:
    def __init__(self, canonical_identifier):
        self._canonical_identifier = canonical_identifier
        self._pending_locks = make_empty_pending_locks_state()
        self.properties = None

    def update(self, amount, lock):
        self._pending_locks = channel.compute_locks_with(self._pending_locks, lock)
        assert self._pending_locks
        if self.properties:
            self.properties = factories.replace(
                self.properties,
                locked_amount=self.properties.locked_amount + amount,
                locksroot=compute_locksroot(self._pending_locks),
                nonce=self.properties.nonce + 1,
            )
        else:
            self.properties = factories.BalanceProofProperties(
                transferred_amount=TokenAmount(0),
                locked_amount=amount,
                nonce=Nonce(1),
                locksroot=compute_locksroot(self._pending_locks),
                canonical_identifier=self._canonical_identifier,
            )


@dataclass
class WithOurAddress:
    our_address: Address
    data: StateChange


class MediatorMixin:
    address_to_privkey: Dict[Address, PrivateKey]
    address_to_client: Dict[Address, Client]
    block_number: BlockNumber
    token_id: TokenAddress

    def __init__(self):
        super().__init__()
        self.partner_to_balance_proof_data: Dict[Address, BalanceProofData] = {}
        self.secrethash_to_secret: Dict[SecretHash, Secret] = {}
        self.waiting_for_unlock: Dict[Secret, Address] = {}
        self.initial_number_of_channels = 2

    def _get_balance_proof_data(self, partner, client_address):
        if partner not in self.partner_to_balance_proof_data:
            client = self.address_to_client[client_address]
            partner_channel = client.address_to_channel[partner]
            self.partner_to_balance_proof_data[partner] = BalanceProofData(
                canonical_identifier=partner_channel.canonical_identifier
            )
        return self.partner_to_balance_proof_data[partner]

    def _update_balance_proof_data(self, partner, amount, expiration, secret, our_address):
        expected = self._get_balance_proof_data(partner, our_address)
        lock = HashTimeLockState(
            amount=amount, expiration=expiration, secrethash=sha256_secrethash(secret)
        )
        expected.update(amount, lock)
        return expected

    def _new_mediator_transfer(
        self, initiator_address, target_address, payment_id, amount, secret, our_address
    ) -> LockedTransferSignedState:
        initiator_pkey = self.address_to_privkey[initiator_address]
        balance_proof_data = self._update_balance_proof_data(
            initiator_address, amount, self.block_number + 10, secret, our_address
        )
        self.secrethash_to_secret[sha256_secrethash(secret)] = secret

        return factories.create(
            factories.LockedTransferSignedStateProperties(  # type: ignore
                **balance_proof_data.properties.__dict__,
                amount=amount,
                expiration=BlockExpiration(self.block_number + 10),
                payment_identifier=payment_id,
                secret=secret,
                initiator=initiator_address,
                target=target_address,
                token=self.token_id,
                sender=initiator_address,
                recipient=our_address,
                pkey=initiator_pkey,
                message_identifier=MessageID(1),
            )
        )

    def _action_init_mediator(
        self, transfer: LockedTransferSignedState, client_address
    ) -> WithOurAddress:
        client = self.address_to_client[client_address]
        initiator_channel = client.address_to_channel[Address(transfer.initiator)]
        target_channel = client.address_to_channel[Address(transfer.target)]
        assert isinstance(target_channel, NettingChannelState)

        action = ActionInitMediator(
            candidate_route_states=[factories.make_route_from_channel(target_channel)],
            from_hop=factories.make_hop_to_channel(initiator_channel),
            from_transfer=transfer,
            balance_proof=transfer.balance_proof,
            sender=transfer.balance_proof.sender,
        )
        return WithOurAddress(our_address=client_address, data=action)

    def _unwrap(self, with_our_address: WithOurAddress):
        our_address = with_our_address.our_address
        data = with_our_address.data
        client = self.address_to_client[our_address]
        return data, client, our_address

    @rule(
        target=init_mediators,
        # from_channel=address_pairs,
        # to_channel=address_pairs,
        payment_id=payment_id(),  # pylint: disable=no-value-for-parameter
        amount=integers(min_value=1, max_value=100),
        secret=secret(),  # pylint: disable=no-value-for-parameter
    )
    def valid_init_mediator(self, from_channel, to_channel, payment_id, amount, secret):
        our_address = from_channel.our_address
        assume(to_channel.our_address == our_address)  # FIXME this will be too slow
        client = self.address_to_client[our_address]

        from_partner = from_channel.partner_address
        to_partner = to_channel.partner_address
        assume(from_partner != to_partner)

        transfer = self._new_mediator_transfer(
            from_partner, to_partner, payment_id, amount, secret, our_address
        )
        client_data = self._action_init_mediator(transfer, our_address)
        result = node.state_transition(client.chain_state, client_data.data)

        assert event_types_match(result.events, SendProcessed, SendLockedTransfer)

        return client_data

    @rule(target=secret_requests, previous_action_with_address=consumes(init_mediators))
    def valid_receive_secret_reveal(self, previous_action_with_address):
        previous_action, client, our_address = self._unwrap(previous_action_with_address)

        secret = self.secrethash_to_secret[previous_action.from_transfer.lock.secrethash]
        sender = previous_action.from_transfer.target
        recipient = previous_action.from_transfer.initiator

        action = ReceiveSecretReveal(secret=secret, sender=sender)
        result = node.state_transition(client.chain_state, action)

        expiration = previous_action.from_transfer.lock.expiration
        in_time = self.block_number < expiration - DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS
        still_waiting = self.block_number < expiration + DEFAULT_WAIT_BEFORE_LOCK_REMOVAL

        if (
            in_time
            and self.channel_opened(sender, our_address)  # pylint: disable=no-member
            and self.channel_opened(recipient, our_address)  # pylint: disable=no-member
        ):
            assert event_types_match(
                result.events, SendSecretReveal, SendUnlock, EventUnlockSuccess
            )
            self.event("Unlock successful.")
            self.waiting_for_unlock[secret] = recipient
        elif still_waiting and self.channel_opened(
            recipient, our_address
        ):  # pylint: disable=no-member
            assert event_types_match(result.events, SendSecretReveal)
            self.event("Unlock failed, secret revealed too late.")
        else:
            assert not result.events
            self.event("ReceiveSecretRevealed after removal of lock - dropped.")
        return WithOurAddress(our_address=our_address, data=action)

    @rule(previous_action_with_address=secret_requests)
    def replay_receive_secret_reveal(self, previous_action_with_address):
        previous_action, client, _ = self._unwrap(previous_action_with_address)
        result = node.state_transition(client.chain_state, previous_action)
        assert not result.events

    # pylint: disable=no-value-for-parameter
    @rule(previous_action_with_address=secret_requests, invalid_sender=address())
    # pylint: enable=no-value-for-parameter
    def replay_receive_secret_reveal_scrambled_sender(
        self, previous_action_with_address, invalid_sender
    ):
        previous_action, client, _ = self._unwrap(previous_action_with_address)
        action = ReceiveSecretReveal(previous_action.secret, invalid_sender)
        result = node.state_transition(client.chain_state, action)
        assert not result.events

    # pylint: disable=no-value-for-parameter
    @rule(previous_action_with_address=init_mediators, secret=secret())
    # pylint: enable=no-value-for-parameter
    def wrong_secret_receive_secret_reveal(self, previous_action_with_address, secret):
        previous_action, client, _ = self._unwrap(previous_action_with_address)
        sender = previous_action.from_transfer.target
        action = ReceiveSecretReveal(secret, sender)
        result = node.state_transition(client.chain_state, action)
        assert not result.events

    # pylint: disable=no-value-for-parameter
    @rule(
        target=secret_requests,
        previous_action_with_address=consumes(init_mediators),
        invalid_sender=address(),
    )
    # pylint: enable=no-value-for-parameter
    def wrong_address_receive_secret_reveal(self, previous_action_with_address, invalid_sender):
        previous_action, client, our_address = self._unwrap(previous_action_with_address)
        secret = self.secrethash_to_secret[previous_action.from_transfer.lock.secrethash]
        invalid_action = ReceiveSecretReveal(secret, invalid_sender)
        result = node.state_transition(client.chain_state, invalid_action)
        assert not result.events

        valid_sender = previous_action.from_transfer.target
        valid_action = ReceiveSecretReveal(secret, valid_sender)
        return WithOurAddress(our_address=our_address, data=valid_action)


class OnChainMixin:

    block_number: BlockNumber

    @rule(number=integers(min_value=1, max_value=50))
    def new_blocks(self, number):
        for _ in range(number):
            block_state_change = Block(
                block_number=BlockNumber(self.block_number + 1),
                gas_limit=BlockGasLimit(1),
                block_hash=make_block_hash(),
            )
            for client in self.address_to_client.values():
                events = []
                result = node.state_transition(client.chain_state, block_state_change)
                events.extend(result.events)
            # TODO assert on events

            self.block_number += 1

    @rule(reference=routes, target=routes)
    def open_channel(self, reference):
        address = self.new_channel_with_transaction(reference.initiator)
        return self.routes_for_new_channel(reference.initiator, address)

    def routes_for_new_channel(self, from_address, to_address):  # pylint: disable=all
        # TODO
        return multiple()

    @rule(reference=consumes(routes))
    def settle_channel(self, reference):
        client = self.address_to_client[reference.initiator]
        channel = client.address_to_channel[reference.hops[1]]

        channel_settled_state_change = ContractReceiveChannelSettled(
            transaction_hash=factories.make_transaction_hash(),
            canonical_identifier=factories.make_canonical_identifier(
                chain_identifier=channel.chain_id,
                token_network_address=channel.token_network_address,
                channel_identifier=channel.identifier,
            ),
            block_number=self.block_number + 1,
            block_hash=factories.make_block_hash(),
            our_transferred_amount=0,
            partner_transferred_amount=0,
            our_onchain_locksroot=LOCKSROOT_OF_NO_LOCKS,
            partner_onchain_locksroot=LOCKSROOT_OF_NO_LOCKS,
        )

        node.state_transition(client.chain_state, channel_settled_state_change)


class MediatorStateMachine(MediatorMixin, ChainStateStateMachine):
    pass


class OnChainStateMachine(OnChainMixin, ChainStateStateMachine):
    def create_network(self):
        client = self.new_client()
        partners = [self.new_channel_with_transaction(client) for _ in range(3)]
        return [Route(hops=(client, partner)) for partner in partners]


class MultiChannelMediatorStateMachine(MediatorMixin, OnChainMixin, ChainStateStateMachine):
    pass


class DirectTransfersStateMachine(InitiatorMixin, TargetMixin, ChainStateStateMachine):
    def create_network(self):
        address1 = self.new_client()
        address2 = self.new_client()
        self.new_channel_with_transaction(address1, address2)
        return [Route(hops=(address1, address2))]


# Skipped tests are temporarily broken during the ongoing
# test restructuring that begun with issue #4013
TestMediator = pytest.mark.skip(MediatorStateMachine.TestCase)
TestOnChain = OnChainStateMachine.TestCase
TestMultiChannelMediator = pytest.mark.skip(MultiChannelMediatorStateMachine.TestCase)
TestDirectTransfers = DirectTransfersStateMachine.TestCase


# use of hypothesis.stateful.multiple() breaks the failed-example code
# generation at the moment, this function is a temporary workaround
def unwrap_multiple(multiple_results):
    values = multiple_results.values
    return values[0] if values else None


def test_regression_malicious_secret_request_handled_properly():
    state = DirectTransfersStateMachine()
    state.replay_path = True

    v1 = unwrap_multiple(state.initialize_all(block_number=1, random=Random(), random_seed=None))
    v2 = state.valid_init_initiator(route=v1, amount=1, payment_id=1, secret=b"\x00" * 32)
    v3 = state.process_send_locked_transfer(source=v2)
    state.process_secret_request_with_wrong_amount(source=v3, wrong_amount=0)
    state.replay_init_initiator(previous=v2)

    state.teardown()
