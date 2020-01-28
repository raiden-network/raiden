from collections import Counter, defaultdict
from dataclasses import dataclass, field
from random import Random
from typing import Dict, List, Set

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
from raiden.messages.transfers import SecretRequest
from raiden.settings import DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS, DEFAULT_WAIT_BEFORE_LOCK_REMOVAL
from raiden.tests.utils import factories
from raiden.tests.utils.factories import make_block_hash
from raiden.transfer import channel, node
from raiden.transfer.architecture import StateChange
from raiden.transfer.channel import compute_locksroot
from raiden.transfer.events import EventPaymentSentFailed, SendProcessed
from raiden.transfer.mediated_transfer.events import (
    EventUnlockSuccess,
    SendLockedTransfer,
    SendSecretReveal,
    SendUnlock,
)
from raiden.transfer.mediated_transfer.state import LockedTransferSignedState
from raiden.transfer.mediated_transfer.state_change import (
    ActionInitInitiator,
    ActionInitMediator,
    ReceiveSecretRequest,
    ReceiveSecretReveal,
    TransferDescriptionWithSecretState,
)
from raiden.transfer.state import (
    ChainState,
    ChannelState,
    HashTimeLockState,
    NettingChannelState,
    NetworkState,
    TokenNetworkGraphState,
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
class AddressPair:
    our_address: Address
    partner_address: Address


address_pairs = Bundle("address_pairs")
# shared bundle of ChainStateStateMachine and all mixin classes
# contains address pairs for all existing channels


AddressToAmount = Dict[Address, TokenAmount]


def make_tokenamount_defaultdict():
    return defaultdict(lambda: TokenAmount(0))


@dataclass
class Client:
    chain_state: ChainState

    address_to_channel: Dict[Address, ChannelState] = field(default_factory=dict)
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

    def assert_monotonicity_invariants(self):
        """ Assert all monotonicity properties stated in Raiden specification """
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
        """ Assert all channel state invariants given in the Raiden specification """
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
        self.address_to_privkey: Dict[Address, PrivateKey] = dict()
        self.address_to_client: Dict[Address, Client] = dict()
        self.initial_number_of_channels = 1
        self.number_of_clients = 1

        super().__init__()

    def new_channel(self, client_address: Address) -> AddressPair:
        """Create a new partner address with private key and channel. The
        private key and channels are listed in the instance's dictionaries,
        the address is returned and should be added to the partners Bundle.
        """
        partner_privkey, partner_address = factories.make_privkey_address()

        self.address_to_privkey[partner_address] = partner_privkey
        client = self.address_to_client[client_address]
        client.address_to_channel[partner_address] = factories.create(
            factories.NettingChannelStateProperties(
                our_state=factories.NettingChannelEndStateProperties(
                    balance=TokenAmount(1000), address=client_address
                ),
                partner_state=factories.NettingChannelEndStateProperties(
                    balance=TokenAmount(1000), address=partner_address
                ),
                canonical_identifier=factories.make_canonical_identifier(
                    token_network_address=self.token_network_address
                ),
            )
        )

        return AddressPair(our_address=client_address, partner_address=partner_address)

    def new_channel_with_transaction(self, client_address: Address) -> AddressPair:
        client = self.address_to_client[client_address]
        address_pair = self.new_channel(client_address)

        partner_address = address_pair.partner_address
        channel_state = client.address_to_channel[partner_address]
        assert isinstance(channel_state, NettingChannelState)
        channel_new_state_change = ContractReceiveChannelNew(
            transaction_hash=factories.make_transaction_hash(),
            channel_state=channel_state,
            block_number=self.block_number,
            block_hash=factories.make_block_hash(),
        )
        node.state_transition(client.chain_state, channel_new_state_change)
        node.state_transition(client.chain_state, channel_new_state_change)
        client.chain_state.nodeaddresses_to_networkstates[partner_address] = NetworkState.REACHABLE

        return address_pair

    @initialize(
        target=address_pairs,
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
            network_graph=TokenNetworkGraphState(self.token_network_address),
        )

        self.token_network_registry_address = factories.make_token_network_registry_address()
        self.token_network_registry_state = TokenNetworkRegistryState(
            self.token_network_registry_address, [self.token_network_state]
        )

        channels: List[NettingChannelState] = []
        for _ in range(self.number_of_clients):
            private_key, address = factories.make_privkey_address()
            self.address_to_privkey[address] = private_key

            chain_state = ChainState(
                pseudo_random_generator=self.random,
                block_number=self.block_number,
                block_hash=self.block_hash,
                our_address=address,
                chain_id=factories.UNIT_CHAIN_ID,
            )
            chain_state.identifiers_to_tokennetworkregistries[
                self.token_network_registry_address
            ] = self.token_network_registry_state

            chain_state.tokennetworkaddresses_to_tokennetworkregistryaddresses[
                self.token_network_address
            ] = self.token_network_registry_address

            self.address_to_client[address] = Client(chain_state=chain_state)

            channels.extend(
                self.new_channel_with_transaction(client_address=address)
                for _ in range(self.initial_number_of_channels)
            )

        return multiple(*channels)

    def event(self, description):
        """ Wrapper for hypothesis' event function.

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
        client = self.address_to_client[client_address]
        needed_channel = client.address_to_channel[partner_address]
        return channel.get_status(needed_channel) == ChannelState.STATE_OPENED


class InitiatorMixin:
    address_to_client: dict
    block_number: BlockNumber

    def __init__(self):
        super().__init__()
        self.used_secrets: Set[Secret] = set()
        self.processed_secret_requests: Set[SecretRequest] = set()
        self.initiated: Set[Secret] = set()

    def _get_initiator_client(self, transfer: TransferDescriptionWithSecretState):
        return self.address_to_client[transfer.initiator]

    def _action_init_initiator(self, transfer: TransferDescriptionWithSecretState):
        client = self._get_initiator_client(transfer)
        channel = client.address_to_channel[transfer.target]
        if transfer.secrethash not in client.expected_expiry:
            client.expected_expiry[transfer.secrethash] = self.block_number + 10
        return ActionInitInitiator(transfer, [factories.make_route_from_channel(channel)])

    def _receive_secret_request(self, transfer: TransferDescriptionWithSecretState):
        client = self._get_initiator_client(transfer)
        secrethash = sha256_secrethash(transfer.secret)
        return ReceiveSecretRequest(
            payment_identifier=transfer.payment_identifier,
            amount=transfer.amount,
            expiration=client.expected_expiry[transfer.secrethash],
            secrethash=secrethash,
            sender=Address(transfer.target),
        )

    def _new_transfer_description(self, address_pair, payment_id, amount, secret):
        self.used_secrets.add(secret)

        return TransferDescriptionWithSecretState(
            token_network_registry_address=self.token_network_registry_address,
            payment_identifier=payment_id,
            amount=amount,
            token_network_address=self.token_network_address,
            initiator=address_pair.our_address,
            target=address_pair.partner_address,
            secret=secret,
        )

    def _invalid_authentic_secret_request(self, previous, action):
        client = self._get_initiator_client(previous.transfer)
        result = node.state_transition(client.chain_state, action)
        if action.secrethash in self.processed_secret_requests or self._is_removed(previous):
            assert not result.events
        else:
            self.processed_secret_requests.add(action.secrethash)

    @staticmethod
    def _unauthentic_secret_request(action, client):
        result = node.state_transition(client.chain_state, action)
        assert not result.events

    def _available_amount(self, address_pair):
        client = self.address_to_client[address_pair.our_address]
        netting_channel = client.address_to_channel[address_pair.partner_address]
        return channel.get_distributable(netting_channel.our_state, netting_channel.partner_state)

    def _assume_channel_opened(self, action):
        assume(self.channel_opened(action.transfer.target, action.transfer.initiator))

    def _is_removed(self, action):
        client = self._get_initiator_client(action.transfer)
        expiry = client.expected_expiry[action.transfer.secrethash]
        return self.block_number >= expiry + DEFAULT_WAIT_BEFORE_LOCK_REMOVAL

    init_initiators = Bundle("init_initiators")

    @rule(
        target=init_initiators,
        address_pair=address_pairs,
        payment_id=payment_id(),  # pylint: disable=no-value-for-parameter
        amount=integers(min_value=1, max_value=100),
        secret=secret(),  # pylint: disable=no-value-for-parameter
    )
    def valid_init_initiator(self, address_pair, payment_id, amount, secret):
        assume(amount <= self._available_amount(address_pair))
        assume(secret not in self.used_secrets)

        transfer = self._new_transfer_description(address_pair, payment_id, amount, secret)
        action = self._action_init_initiator(transfer)
        client = self.address_to_client[address_pair.our_address]
        result = node.state_transition(client.chain_state, action)

        assert event_types_match(result.events, SendLockedTransfer)

        self.initiated.add(transfer.secret)
        client.expected_expiry[transfer.secrethash] = self.block_number + 10

        return action

    @rule(
        address_pair=address_pairs,
        payment_id=payment_id(),  # pylint: disable=no-value-for-parameter
        excess_amount=integers(min_value=1),
        secret=secret(),  # pylint: disable=no-value-for-parameter
    )
    def exceeded_capacity_init_initiator(self, address_pair, payment_id, excess_amount, secret):
        amount = self._available_amount(address_pair) + excess_amount
        transfer = self._new_transfer_description(address_pair, payment_id, amount, secret)
        action = self._action_init_initiator(transfer)
        client = self.address_to_client[address_pair.our_address]
        result = node.state_transition(client.chain_state, action)
        assert event_types_match(result.events, EventPaymentSentFailed)
        self.event("ActionInitInitiator failed: Amount exceeded")

    @rule(
        previous_action=init_initiators,
        address_pair=address_pairs,
        payment_id=payment_id(),  # pylint: disable=no-value-for-parameter
        amount=integers(min_value=1),
    )
    def used_secret_init_initiator(self, previous_action, address_pair, payment_id, amount):
        assume(not self._is_removed(previous_action))
        client = self._get_initiator_client(previous_action.transfer)
        secret = previous_action.transfer.secret
        transfer = self._new_transfer_description(address_pair, payment_id, amount, secret)
        action = self._action_init_initiator(transfer)
        result = node.state_transition(client.chain_state, action)
        assert not result.events
        self.event("ActionInitInitiator failed: Secret already in use.")

    @rule(previous_action=init_initiators)
    def replay_init_initator(self, previous_action):
        assume(not self._is_removed(previous_action))
        client = self._get_initiator_client(previous_action.transfer)
        result = node.state_transition(client.chain_state, previous_action)
        assert not result.events

    @rule(previous_action=init_initiators)
    def valid_secret_request(self, previous_action):
        action = self._receive_secret_request(previous_action.transfer)
        self._assume_channel_opened(previous_action)
        client = self._get_initiator_client(previous_action.transfer)
        result = node.state_transition(client.chain_state, action)
        if action.secrethash in self.processed_secret_requests:
            assert not result.events
            self.event("Valid SecretRequest dropped due to previous invalid one.")
        elif self._is_removed(previous_action):
            assert not result.events
            self.event("Otherwise valid SecretRequest dropped due to expired lock.")
        else:
            assert event_types_match(result.events, SendSecretReveal)
            self.event("Valid SecretRequest accepted.")
            self.processed_secret_requests.add(action.secrethash)

    @rule(previous_action=init_initiators, amount=integers())
    def wrong_amount_secret_request(self, previous_action, amount):
        assume(amount != previous_action.transfer.amount)
        self._assume_channel_opened(previous_action)
        transfer = deepcopy(previous_action.transfer)
        transfer.amount = amount
        action = self._receive_secret_request(transfer)
        self._invalid_authentic_secret_request(previous_action, action)

    @rule(
        previous_action=init_initiators, secret=secret()  # pylint: disable=no-value-for-parameter
    )
    def secret_request_with_wrong_secrethash(self, previous_action, secret):
        assume(sha256_secrethash(secret) != sha256_secrethash(previous_action.transfer.secret))
        self._assume_channel_opened(previous_action)
        transfer = deepcopy(previous_action.transfer)
        transfer.secret = secret
        action = self._receive_secret_request(transfer)
        client = self._get_initiator_client(transfer)
        return self._unauthentic_secret_request(action, client)

    @rule(previous_action=init_initiators, payment_identifier=integers())
    def secret_request_with_wrong_payment_id(self, previous_action, payment_identifier):
        assume(payment_identifier != previous_action.transfer.payment_identifier)
        self._assume_channel_opened(previous_action)
        transfer = deepcopy(previous_action.transfer)
        transfer.payment_identifier = payment_identifier
        action = self._receive_secret_request(transfer)
        client = self._get_initiator_client(transfer)
        self._unauthentic_secret_request(action, client)


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
        self.partner_to_balance_proof_data: Dict[Address, BalanceProofData] = dict()
        self.secrethash_to_secret: Dict[SecretHash, Secret] = dict()
        self.waiting_for_unlock: Dict[Secret, Address] = dict()
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

    init_mediators = Bundle("init_mediators")
    secret_requests = Bundle("secret_requests")
    unlocks = Bundle("unlocks")

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
            route_states=[factories.make_route_from_channel(target_channel)],
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
        from_channel=address_pairs,
        to_channel=address_pairs,
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
            and self.channel_opened(sender, our_address)
            and self.channel_opened(recipient, our_address)
        ):
            assert event_types_match(
                result.events, SendSecretReveal, SendUnlock, EventUnlockSuccess
            )
            self.event("Unlock successful.")
            self.waiting_for_unlock[secret] = recipient
        elif still_waiting and self.channel_opened(recipient, our_address):
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
                events = list()
                result = node.state_transition(client.chain_state, block_state_change)
                events.extend(result.events)
            # TODO assert on events

            self.block_number += 1

    @rule(reference=address_pairs, target=address_pairs)
    def open_channel(self, reference):
        return self.new_channel_with_transaction(reference.our_address)

    @rule(address_pair=consumes(address_pairs))
    def settle_channel(self, address_pair):
        client = self.address_to_client[address_pair.our_address]
        channel = client.address_to_channel[address_pair.partner_address]

        channel_settled_state_change = ContractReceiveChannelSettled(
            transaction_hash=factories.make_transaction_hash(),
            canonical_identifier=factories.make_canonical_identifier(
                chain_identifier=channel.chain_id,
                token_network_address=channel.token_network_address,
                channel_identifier=channel.identifier,
            ),
            block_number=self.block_number + 1,
            block_hash=factories.make_block_hash(),
            our_onchain_locksroot=LOCKSROOT_OF_NO_LOCKS,
            partner_onchain_locksroot=LOCKSROOT_OF_NO_LOCKS,
        )

        node.state_transition(client.chain_state, channel_settled_state_change)


class InitiatorStateMachine(InitiatorMixin, ChainStateStateMachine):
    pass


class MediatorStateMachine(MediatorMixin, ChainStateStateMachine):
    pass


class OnChainStateMachine(OnChainMixin, ChainStateStateMachine):
    pass


class MultiChannelInitiatorStateMachine(InitiatorMixin, OnChainMixin, ChainStateStateMachine):
    pass


class MultiChannelMediatorStateMachine(MediatorMixin, OnChainMixin, ChainStateStateMachine):
    pass


class FullStateMachine(InitiatorMixin, MediatorMixin, OnChainMixin, ChainStateStateMachine):
    pass


TestInitiator = InitiatorStateMachine.TestCase
TestMediator = MediatorStateMachine.TestCase
TestOnChain = OnChainStateMachine.TestCase
TestMultiChannelInitiator = MultiChannelInitiatorStateMachine.TestCase
TestMultiChannelMediator = MultiChannelMediatorStateMachine.TestCase
TestFullStateMachine = FullStateMachine.TestCase


# use of hypothesis.stateful.multiple() breaks the failed-example code
# generation at the moment, this function is a temporary workaround
def unwrap_multiple(multiple_results):
    values = multiple_results.values
    return values[0] if values else None


def test_regression_malicious_secret_request_handled_properly():
    state = InitiatorStateMachine()
    state.replay_path = True

    v1 = unwrap_multiple(state.initialize_all(block_number=1, random=Random(), random_seed=None))
    v2 = state.valid_init_initiator(address_pair=v1, amount=1, payment_id=1, secret=b"\x00" * 32)
    state.wrong_amount_secret_request(amount=0, previous_action=v2)
    state.replay_init_initator(previous_action=v2)

    state.teardown()
