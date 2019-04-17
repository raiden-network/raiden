import gevent
import structlog
from eth_utils import is_binary_address, is_hex, to_bytes, to_checksum_address
from gevent import Greenlet

import raiden.blockchain.events as blockchain_events
from raiden import waiting
from raiden.constants import (
    GENESIS_BLOCK_NUMBER,
    RED_EYES_PER_TOKEN_NETWORK_LIMIT,
    SECRET_HASH_HEXSTRING_LENGTH,
    SECRET_HEXSTRING_LENGTH,
    UINT256_MAX,
    Environment,
)
from raiden.exceptions import (
    AlreadyRegisteredTokenAddress,
    ChannelNotFound,
    DepositMismatch,
    DepositOverLimit,
    DuplicatedChannelError,
    InsufficientFunds,
    InsufficientGasReserve,
    InvalidAddress,
    InvalidAmount,
    InvalidSecretOrSecretHash,
    InvalidSettleTimeout,
    RaidenRecoverableError,
    TokenNotRegistered,
    UnknownTokenAddress,
)
from raiden.messages import RequestMonitoring
from raiden.settings import DEFAULT_RETRY_TIMEOUT, DEVELOPMENT_CONTRACT_VERSION
from raiden.transfer import architecture, views
from raiden.transfer.events import (
    EventPaymentReceivedSuccess,
    EventPaymentSentFailed,
    EventPaymentSentSuccess,
)
from raiden.transfer.mediated_transfer.state import LockedTransferState
from raiden.transfer.state import BalanceProofSignedState, NettingChannelState, TransferTask
from raiden.transfer.state_change import ActionChannelClose
from raiden.utils import pex, sha3, typing
from raiden.utils.gas_reserve import has_enough_gas_reserve

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name

EVENTS_PAYMENT_HISTORY_RELATED = (
    EventPaymentSentSuccess,
    EventPaymentSentFailed,
    EventPaymentReceivedSuccess,
)


def event_filter_for_payments(
        event: architecture.Event,
        token_network_identifier: typing.TokenNetworkID = None,
        partner_address: typing.Address = None,
) -> bool:
    """Filters out non payment history related events

    - If no other args are given, all payment related events match
    - If a token network identifier is given then only payment events for that match
    - If a partner is also given then if the event is a payment sent event and the
      target matches it's returned. If it's a payment received and the initiator matches
      then it's returned.
    """
    is_matching_event = (
        isinstance(event, EVENTS_PAYMENT_HISTORY_RELATED) and
        (
            token_network_identifier is None or
            token_network_identifier == event.token_network_identifier
        )
    )
    if not is_matching_event:
        return False

    sent_and_target_matches = (
        isinstance(event, (EventPaymentSentFailed, EventPaymentSentSuccess)) and
        (
            partner_address is None or
            event.target == partner_address
        )
    )
    received_and_initiator_matches = (
        isinstance(event, EventPaymentReceivedSuccess) and
        (
            partner_address is None or
            event.initiator == partner_address
        )
    )
    return sent_and_target_matches or received_and_initiator_matches


def flatten_transfer(transfer: LockedTransferState, role: str) -> typing.Dict[str, typing.Any]:
    return {
        'payment_identifier': str(transfer.payment_identifier),
        'token_address': to_checksum_address(transfer.token),
        'token_network_identifier': to_checksum_address(
            transfer.balance_proof.token_network_identifier,
        ),
        'channel_identifier': str(transfer.balance_proof.channel_identifier),
        'initiator': to_checksum_address(transfer.initiator),
        'target': to_checksum_address(transfer.target),
        'transferred_amount': str(transfer.balance_proof.transferred_amount),
        'locked_amount': str(transfer.balance_proof.locked_amount),
        'role': role,
    }


def get_transfer_from_task(
        secrethash: typing.SecretHash,
        transfer_task: TransferTask,
) -> LockedTransferState:
    transfer = None
    role = views.role_from_transfer_task(transfer_task)

    if role == 'initiator':
        transfer = transfer_task.manager_state.initiator_transfers[secrethash].transfer
    elif role == 'mediator':
        pairs = transfer_task.mediator_state.transfers_pair
        if pairs:
            transfer = pairs[-1].payer_transfer
        elif transfer_task.mediator_state.waiting_transfer:
            transfer = transfer_task.mediator_state.waiting_transfer.transfer
    elif role == 'target':
        transfer = transfer_task.target_state.transfer

    return transfer, role


def transfer_tasks_view(
        transfer_tasks: typing.Dict[typing.SecretHash, TransferTask],
        token_address: typing.TokenAddress = None,
        channel_id: typing.ChannelID = None,
) -> typing.List[typing.Dict[str, typing.Any]]:
    view = list()

    for secrethash, transfer_task in transfer_tasks.items():
        transfer, role = get_transfer_from_task(secrethash, transfer_task)

        if transfer is None:
            continue
        if token_address is not None:
            if transfer.token != token_address:
                continue
            elif channel_id is not None:
                if transfer.balance_proof.channel_identifier != channel_id:
                    continue

        view.append(flatten_transfer(transfer, role))

    return view


class RaidenAPI:
    # pylint: disable=too-many-public-methods

    def __init__(self, raiden):
        self.raiden = raiden

    @property
    def address(self):
        return self.raiden.address

    def get_channel(
            self,
            registry_address: typing.PaymentNetworkID,
            token_address: typing.TokenAddress,
            partner_address: typing.Address,
    ) -> NettingChannelState:
        if not is_binary_address(token_address):
            raise InvalidAddress('Expected binary address format for token in get_channel')

        if not is_binary_address(partner_address):
            raise InvalidAddress('Expected binary address format for partner in get_channel')

        channel_list = self.get_channel_list(registry_address, token_address, partner_address)
        assert len(channel_list) <= 1

        if not channel_list:
            raise ChannelNotFound(
                "Channel with partner '{}' for token '{}' could not be found.".format(
                    to_checksum_address(partner_address),
                    to_checksum_address(token_address),
                ),
            )

        return channel_list[0]

    def token_network_register(
            self,
            registry_address: typing.PaymentNetworkID,
            token_address: typing.TokenAddress,
            channel_participant_deposit_limit: typing.TokenAmount,
            token_network_deposit_limit: typing.TokenAmount,
            retry_timeout: typing.NetworkTimeout = DEFAULT_RETRY_TIMEOUT,
    ) -> typing.TokenNetworkAddress:
        """Register the `token_address` in the blockchain. If the address is already
           registered but the event has not been processed this function will block
           until the next block to make sure the event is processed.

        Raises:
            InvalidAddress: If the registry_address or token_address is not a valid address.
            AlreadyRegisteredTokenAddress: If the token is already registered.
            TransactionThrew: If the register transaction failed, this may
                happen because the account has not enough balance to pay for the
                gas or this register call raced with another transaction and lost.
        """

        if not is_binary_address(registry_address):
            raise InvalidAddress('registry_address must be a valid address in binary')

        if not is_binary_address(token_address):
            raise InvalidAddress('token_address must be a valid address in binary')

        if token_address in self.get_tokens_list(registry_address):
            raise AlreadyRegisteredTokenAddress('Token already registered')

        contracts_version = self.raiden.contract_manager.contracts_version

        registry = self.raiden.chain.token_network_registry(registry_address)

        try:
            if contracts_version == DEVELOPMENT_CONTRACT_VERSION:
                return registry.add_token_with_limits(
                    token_address=token_address,
                    channel_participant_deposit_limit=channel_participant_deposit_limit,
                    token_network_deposit_limit=token_network_deposit_limit,
                )
            else:
                return registry.add_token_without_limits(
                    token_address=token_address,
                )
        except RaidenRecoverableError as e:
            if 'Token already registered' in str(e):
                raise AlreadyRegisteredTokenAddress('Token already registered')
            # else
            raise

        finally:
            # Assume the transaction failed because the token is already
            # registered with the smart contract and this node has not yet
            # polled for the event (otherwise the check above would have
            # failed).
            #
            # To provide a consistent view to the user, wait one block, this
            # will guarantee that the events have been processed.
            next_block = self.raiden.get_block_number() + 1
            waiting.wait_for_block(self.raiden, next_block, retry_timeout)

    def token_network_connect(
            self,
            registry_address: typing.PaymentNetworkID,
            token_address: typing.TokenAddress,
            funds: typing.TokenAmount,
            initial_channel_target: int = 3,
            joinable_funds_target: float = 0.4,
    ) -> None:
        """ Automatically maintain channels open for the given token network.

        Args:
            token_address: the ERC20 token network to connect to.
            funds: the amount of funds that can be used by the ConnectionMananger.
            initial_channel_target: number of channels to open proactively.
            joinable_funds_target: fraction of the funds that will be used to join
                channels opened by other participants.
        """
        if not is_binary_address(registry_address):
            raise InvalidAddress('registry_address must be a valid address in binary')
        if not is_binary_address(token_address):
            raise InvalidAddress('token_address must be a valid address in binary')

        token_network_identifier = views.get_token_network_identifier_by_token_address(
            chain_state=views.state_from_raiden(self.raiden),
            payment_network_id=registry_address,
            token_address=token_address,
        )

        connection_manager = self.raiden.connection_manager_for_token_network(
            token_network_identifier,
        )

        has_enough_reserve, estimated_required_reserve = has_enough_gas_reserve(
            raiden=self.raiden,
            channels_to_open=initial_channel_target,
        )

        if not has_enough_reserve:
            raise InsufficientGasReserve((
                'The account balance is below the estimated amount necessary to '
                'finish the lifecycles of all active channels. A balance of at '
                f'least {estimated_required_reserve} wei is required.'
            ))

        connection_manager.connect(
            funds=funds,
            initial_channel_target=initial_channel_target,
            joinable_funds_target=joinable_funds_target,
        )

    def token_network_leave(
            self,
            registry_address: typing.PaymentNetworkID,
            token_address: typing.TokenAddress,
    ) -> typing.List[NettingChannelState]:
        """ Close all channels and wait for settlement. """
        if not is_binary_address(registry_address):
            raise InvalidAddress('registry_address must be a valid address in binary')
        if not is_binary_address(token_address):
            raise InvalidAddress('token_address must be a valid address in binary')

        if token_address not in self.get_tokens_list(registry_address):
            raise UnknownTokenAddress('token_address unknown')

        token_network_identifier = views.get_token_network_identifier_by_token_address(
            chain_state=views.state_from_raiden(self.raiden),
            payment_network_id=registry_address,
            token_address=token_address,
        )

        connection_manager = self.raiden.connection_manager_for_token_network(
            token_network_identifier,
        )

        return connection_manager.leave(registry_address)

    def channel_open(
            self,
            registry_address: typing.PaymentNetworkID,
            token_address: typing.TokenAddress,
            partner_address: typing.Address,
            settle_timeout: typing.BlockTimeout = None,
            retry_timeout: typing.NetworkTimeout = DEFAULT_RETRY_TIMEOUT,
    ) -> typing.ChannelID:
        """ Open a channel with the peer at `partner_address`
        with the given `token_address`.
        """
        if settle_timeout is None:
            settle_timeout = self.raiden.config['settle_timeout']

        if settle_timeout < self.raiden.config['reveal_timeout'] * 2:
            raise InvalidSettleTimeout(
                'settle_timeout can not be smaller than double the reveal_timeout',
            )

        if not is_binary_address(registry_address):
            raise InvalidAddress('Expected binary address format for registry in channel open')

        if not is_binary_address(token_address):
            raise InvalidAddress('Expected binary address format for token in channel open')

        if not is_binary_address(partner_address):
            raise InvalidAddress('Expected binary address format for partner in channel open')

        chain_state = views.state_from_raiden(self.raiden)
        channel_state = views.get_channelstate_for(
            chain_state=chain_state,
            payment_network_id=registry_address,
            token_address=token_address,
            partner_address=partner_address,
        )

        if channel_state:
            raise DuplicatedChannelError('Channel with given partner address already exists')

        registry = self.raiden.chain.token_network_registry(registry_address)
        token_network_address = registry.get_token_network(token_address)

        if token_network_address is None:
            raise TokenNotRegistered(
                'Token network for token %s does not exist' % to_checksum_address(token_address),
            )

        token_network = self.raiden.chain.token_network(
            registry.get_token_network(token_address),
        )

        with self.raiden.gas_reserve_lock:
            has_enough_reserve, estimated_required_reserve = has_enough_gas_reserve(
                self.raiden,
                channels_to_open=1,
            )

            if not has_enough_reserve:
                raise InsufficientGasReserve((
                    'The account balance is below the estimated amount necessary to '
                    'finish the lifecycles of all active channels. A balance of at '
                    f'least {estimated_required_reserve} wei is required.'
                ))

            try:
                token_network.new_netting_channel(
                    partner=partner_address,
                    settle_timeout=settle_timeout,
                    given_block_identifier=views.state_from_raiden(self.raiden).block_hash,
                )
            except DuplicatedChannelError:
                log.info('partner opened channel first')

        waiting.wait_for_newchannel(
            raiden=self.raiden,
            payment_network_id=registry_address,
            token_address=token_address,
            partner_address=partner_address,
            retry_timeout=retry_timeout,
        )
        chain_state = views.state_from_raiden(self.raiden)
        channel_state = views.get_channelstate_for(
            chain_state=chain_state,
            payment_network_id=registry_address,
            token_address=token_address,
            partner_address=partner_address,
        )

        assert channel_state, f'channel {channel_state} is gone'

        return channel_state.identifier

    def set_total_channel_deposit(
            self,
            registry_address: typing.PaymentNetworkID,
            token_address: typing.TokenAddress,
            partner_address: typing.Address,
            total_deposit: typing.TokenAmount,
            retry_timeout: typing.NetworkTimeout = DEFAULT_RETRY_TIMEOUT,
    ):
        """ Set the `total_deposit` in the channel with the peer at `partner_address` and the
        given `token_address` in order to be able to do transfers.

        Raises:
            InvalidAddress: If either token_address or partner_address is not
                20 bytes long.
            TransactionThrew: May happen for multiple reasons:
                - If the token approval fails, e.g. the token may validate if
                account has enough balance for the allowance.
                - The deposit failed, e.g. the allowance did not set the token
                aside for use and the user spent it before deposit was called.
                - The channel was closed/settled between the allowance call and
                the deposit call.
            AddressWithoutCode: The channel was settled during the deposit
                execution.
            DepositOverLimit: The total deposit amount is higher than the limit.
        """
        chain_state = views.state_from_raiden(self.raiden)

        token_addresses = views.get_token_identifiers(
            chain_state,
            registry_address,
        )
        channel_state = views.get_channelstate_for(
            chain_state=chain_state,
            payment_network_id=registry_address,
            token_address=token_address,
            partner_address=partner_address,
        )

        if not is_binary_address(token_address):
            raise InvalidAddress('Expected binary address format for token in channel deposit')

        if not is_binary_address(partner_address):
            raise InvalidAddress('Expected binary address format for partner in channel deposit')

        if token_address not in token_addresses:
            raise UnknownTokenAddress('Unknown token address')

        if channel_state is None:
            raise InvalidAddress('No channel with partner_address for the given token')

        if self.raiden.config['environment_type'] == Environment.PRODUCTION:
            per_token_network_deposit_limit = RED_EYES_PER_TOKEN_NETWORK_LIMIT
        else:
            per_token_network_deposit_limit = UINT256_MAX

        token = self.raiden.chain.token(token_address)
        token_network_registry = self.raiden.chain.token_network_registry(registry_address)
        token_network_address = token_network_registry.get_token_network(token_address)
        token_network_proxy = self.raiden.chain.token_network(token_network_address)
        channel_proxy = self.raiden.chain.payment_channel(
            canonical_identifier=channel_state.canonical_identifier,
        )

        if total_deposit == 0:
            raise DepositMismatch('Attempted to deposit with total deposit being 0')

        addendum = total_deposit - channel_state.our_state.contract_balance

        total_network_balance = token.balance_of(registry_address)

        if total_network_balance + addendum > per_token_network_deposit_limit:
            raise DepositOverLimit(
                f'The deposit of {addendum} will exceed the '
                f'token network limit of {per_token_network_deposit_limit}',
            )

        balance = token.balance_of(self.raiden.address)

        functions = token_network_proxy.proxy.contract.functions
        deposit_limit = functions.channel_participant_deposit_limit().call()

        if total_deposit > deposit_limit:
            raise DepositOverLimit(
                f'The additional deposit of {addendum} will exceed the '
                f'channel participant limit of {deposit_limit}',
            )

        # If this check succeeds it does not imply the the `deposit` will
        # succeed, since the `deposit` transaction may race with another
        # transaction.
        if not balance >= addendum:
            msg = 'Not enough balance to deposit. {} Available={} Needed={}'.format(
                pex(token_address),
                balance,
                addendum,
            )
            raise InsufficientFunds(msg)

        # set_total_deposit calls approve
        # token.approve(netcontract_address, addendum)
        channel_proxy.set_total_deposit(
            total_deposit=total_deposit,
            block_identifier=views.state_from_raiden(self.raiden).block_hash,
        )

        target_address = self.raiden.address
        waiting.wait_for_participant_newbalance(
            raiden=self.raiden,
            payment_network_id=registry_address,
            token_address=token_address,
            partner_address=partner_address,
            target_address=target_address,
            target_balance=total_deposit,
            retry_timeout=retry_timeout,
        )

    def channel_close(
            self,
            registry_address: typing.PaymentNetworkID,
            token_address: typing.TokenAddress,
            partner_address: typing.Address,
            retry_timeout: typing.NetworkTimeout = DEFAULT_RETRY_TIMEOUT,
    ):
        """Close a channel opened with `partner_address` for the given
        `token_address`.

        Race condition, this can fail if channel was closed externally.
        """
        self.channel_batch_close(
            registry_address=registry_address,
            token_address=token_address,
            partner_addresses=[partner_address],
            retry_timeout=retry_timeout,
        )

    def channel_batch_close(
            self,
            registry_address: typing.PaymentNetworkID,
            token_address: typing.TokenAddress,
            partner_addresses: typing.List[typing.Address],
            retry_timeout: typing.NetworkTimeout = DEFAULT_RETRY_TIMEOUT,
    ):
        """Close a channel opened with `partner_address` for the given
        `token_address`.

        Race condition, this can fail if channel was closed externally.
        """

        if not is_binary_address(token_address):
            raise InvalidAddress('Expected binary address format for token in channel close')

        if not all(map(is_binary_address, partner_addresses)):
            raise InvalidAddress('Expected binary address format for partner in channel close')

        valid_tokens = views.get_token_identifiers(
            chain_state=views.state_from_raiden(self.raiden),
            payment_network_id=registry_address,
        )
        if token_address not in valid_tokens:
            raise UnknownTokenAddress('Token address is not known.')

        chain_state = views.state_from_raiden(self.raiden)
        channels_to_close = views.filter_channels_by_partneraddress(
            chain_state=chain_state,
            payment_network_id=registry_address,
            token_address=token_address,
            partner_addresses=partner_addresses,
        )

        greenlets: typing.Set[Greenlet] = set()
        for channel_state in channels_to_close:
            channel_close = ActionChannelClose(
                canonical_identifier=channel_state.canonical_identifier,
            )

            greenlets.update(
                self.raiden.handle_state_change(channel_close),
            )

        gevent.joinall(greenlets, raise_error=True)

        channel_ids = [channel_state.identifier for channel_state in channels_to_close]

        waiting.wait_for_close(
            raiden=self.raiden,
            payment_network_id=registry_address,
            token_address=token_address,
            channel_ids=channel_ids,
            retry_timeout=retry_timeout,
        )

    def get_channel_list(
            self,
            registry_address: typing.PaymentNetworkID,
            token_address: typing.TokenAddress = None,
            partner_address: typing.Address = None,
    ) -> typing.List[NettingChannelState]:
        """Returns a list of channels associated with the optionally given
           `token_address` and/or `partner_address`.

        Args:
            token_address: an optionally provided token address
            partner_address: an optionally provided partner address

        Return:
            A list containing all channels the node participates. Optionally
            filtered by a token address and/or partner address.

        Raises:
            KeyError: An error occurred when the token address is unknown to the node.
        """
        if registry_address and not is_binary_address(registry_address):
            raise InvalidAddress('Expected binary address format for registry in get_channel_list')

        if token_address and not is_binary_address(token_address):
            raise InvalidAddress('Expected binary address format for token in get_channel_list')

        if partner_address:
            if not is_binary_address(partner_address):
                raise InvalidAddress(
                    'Expected binary address format for partner in get_channel_list',
                )
            if not token_address:
                raise UnknownTokenAddress('Provided a partner address but no token address')

        if token_address and partner_address:
            channel_state = views.get_channelstate_for(
                chain_state=views.state_from_raiden(self.raiden),
                payment_network_id=registry_address,
                token_address=token_address,
                partner_address=partner_address,
            )

            if channel_state:
                result = [channel_state]
            else:
                result = []

        elif token_address:
            result = views.list_channelstate_for_tokennetwork(
                chain_state=views.state_from_raiden(self.raiden),
                payment_network_id=registry_address,
                token_address=token_address,
            )

        else:
            result = views.list_all_channelstate(
                chain_state=views.state_from_raiden(self.raiden),
            )

        return result

    def get_node_network_state(self, node_address: typing.Address):
        """ Returns the currently network status of `node_address`. """
        return views.get_node_network_status(
            chain_state=views.state_from_raiden(self.raiden),
            node_address=node_address,
        )

    def start_health_check_for(self, node_address: typing.Address):
        """ Returns the currently network status of `node_address`. """
        self.raiden.start_health_check_for(node_address)

    def get_tokens_list(self, registry_address: typing.PaymentNetworkID):
        """Returns a list of tokens the node knows about"""
        tokens_list = views.get_token_identifiers(
            chain_state=views.state_from_raiden(self.raiden),
            payment_network_id=registry_address,
        )
        return tokens_list

    def get_token_network_address_for_token_address(
            self,
            registry_address: typing.PaymentNetworkID,
            token_address: typing.TokenAddress,
    ) -> typing.Optional[typing.TokenNetworkID]:
        return views.get_token_network_identifier_by_token_address(
            chain_state=views.state_from_raiden(self.raiden),
            payment_network_id=registry_address,
            token_address=token_address,
        )

    def transfer_and_wait(
            self,
            registry_address: typing.PaymentNetworkID,
            token_address: typing.TokenAddress,
            amount: typing.TokenAmount,
            target: typing.Address,
            identifier: typing.PaymentID = None,
            transfer_timeout: int = None,
            secret: typing.Secret = None,
            secret_hash: typing.SecretHash = None,
    ):
        """ Do a transfer with `target` with the given `amount` of `token_address`. """
        # pylint: disable=too-many-arguments

        payment_status = self.transfer_async(
            registry_address=registry_address,
            token_address=token_address,
            amount=amount,
            target=target,
            identifier=identifier,
            secret=secret,
            secret_hash=secret_hash,
        )
        payment_status.payment_done.wait(timeout=transfer_timeout)
        return payment_status

    def transfer_async(
            self,
            registry_address: typing.PaymentNetworkID,
            token_address: typing.TokenAddress,
            amount: typing.TokenAmount,
            target: typing.Address,
            identifier: typing.PaymentID = None,
            secret: typing.Secret = None,
            secret_hash: typing.SecretHash = None,
    ):

        if not isinstance(amount, int):
            raise InvalidAmount('Amount not a number')

        if amount <= 0:
            raise InvalidAmount('Amount negative')

        if not is_binary_address(token_address):
            raise InvalidAddress('token address is not valid.')

        if not is_binary_address(target):
            raise InvalidAddress('target address is not valid.')

        if secret is not None:
            if len(secret) != SECRET_HEXSTRING_LENGTH:
                raise InvalidSecretOrSecretHash(
                    'secret length should be ' +
                    str(SECRET_HEXSTRING_LENGTH) +
                    '.',
                )
            if not is_hex(secret):
                raise InvalidSecretOrSecretHash('provided secret is not an hexadecimal string.')
            secret = to_bytes(hexstr=secret)

        if secret_hash is not None:
            if len(secret_hash) != SECRET_HASH_HEXSTRING_LENGTH:
                raise InvalidSecretOrSecretHash(
                    'secret_hash length should be ' +
                    str(SECRET_HASH_HEXSTRING_LENGTH) +
                    '.',
                )
            if not is_hex(secret_hash):
                raise InvalidSecretOrSecretHash('secret_hash is not an hexadecimal string.')
            secret_hash = to_bytes(hexstr=secret_hash)

        if secret is None and secret_hash is not None:
            raise InvalidSecretOrSecretHash('secret_hash without a secret is not supported yet.')

        if secret is not None and secret_hash is not None and secret_hash != sha3(secret):
            raise InvalidSecretOrSecretHash('provided secret and secret_hash do not match.')

        valid_tokens = views.get_token_identifiers(
            views.state_from_raiden(self.raiden),
            registry_address,
        )
        if token_address not in valid_tokens:
            raise UnknownTokenAddress('Token address is not known.')

        log.debug(
            'Initiating transfer',
            initiator=pex(self.raiden.address),
            target=pex(target),
            token=pex(token_address),
            amount=amount,
            identifier=identifier,
        )

        payment_network_identifier = self.raiden.default_registry.address
        token_network_identifier = views.get_token_network_identifier_by_token_address(
            chain_state=views.state_from_raiden(self.raiden),
            payment_network_id=payment_network_identifier,
            token_address=token_address,
        )
        payment_status = self.raiden.mediated_transfer_async(
            token_network_identifier=token_network_identifier,
            amount=amount,
            target=target,
            identifier=identifier,
            secret=secret,
            secret_hash=secret_hash,
        )
        return payment_status

    def get_raiden_events_payment_history_with_timestamps(
            self,
            token_address: typing.TokenAddress = None,
            target_address: typing.Address = None,
            limit: int = None,
            offset: int = None,
    ):
        if token_address and not is_binary_address(token_address):
            raise InvalidAddress(
                'Expected binary address format for token in get_raiden_events_payment_history',
            )

        if target_address and not is_binary_address(target_address):
            raise InvalidAddress(
                'Expected binary address format for '
                'target_address in get_raiden_events_payment_history',
            )

        token_network_identifier = None
        if token_address:
            token_network_identifier = views.get_token_network_identifier_by_token_address(
                chain_state=views.state_from_raiden(self.raiden),
                payment_network_id=self.raiden.default_registry.address,
                token_address=token_address,
            )

        events = [
            event
            for event in self.raiden.wal.storage.get_events_with_timestamps(
                limit=limit,
                offset=offset,
            ) if event_filter_for_payments(
                event=event.wrapped_event,
                token_network_identifier=token_network_identifier,
                partner_address=target_address,
            )
        ]

        return events

    def get_raiden_events_payment_history(
            self,
            token_address: typing.TokenAddress = None,
            target_address: typing.Address = None,
            limit: int = None,
            offset: int = None,
    ):
        timestamped_events = self.get_raiden_events_payment_history_with_timestamps(
            token_address=token_address,
            target_address=target_address,
            limit=limit,
            offset=offset,
        )

        return [event.wrapped_event for event in timestamped_events]

    def get_raiden_internal_events_with_timestamps(self, limit: int = None, offset: int = None):
        return self.raiden.wal.storage.get_events_with_timestamps(limit=limit, offset=offset)

    transfer = transfer_and_wait

    def get_blockchain_events_network(
            self,
            registry_address: typing.PaymentNetworkID,
            from_block: typing.BlockSpecification = GENESIS_BLOCK_NUMBER,
            to_block: typing.BlockSpecification = 'latest',
    ):
        events = blockchain_events.get_token_network_registry_events(
            chain=self.raiden.chain,
            token_network_registry_address=registry_address,
            contract_manager=self.raiden.contract_manager,
            events=blockchain_events.ALL_EVENTS,
            from_block=from_block,
            to_block=to_block,
        )

        return sorted(
            events,
            key=lambda evt: evt.get('block_number'),
            reverse=True,
        )

    def get_blockchain_events_token_network(
            self,
            token_address: typing.TokenAddress,
            from_block: typing.BlockSpecification = GENESIS_BLOCK_NUMBER,
            to_block: typing.BlockSpecification = 'latest',
    ):
        """Returns a list of blockchain events coresponding to the token_address."""

        if not is_binary_address(token_address):
            raise InvalidAddress(
                'Expected binary address format for token in get_blockchain_events_token_network',
            )

        token_network_address = self.raiden.default_registry.get_token_network(
            token_address,
        )

        if token_network_address is None:
            raise UnknownTokenAddress('Token address is not known.')

        returned_events = blockchain_events.get_token_network_events(
            chain=self.raiden.chain,
            token_network_address=token_network_address,
            contract_manager=self.raiden.contract_manager,
            events=blockchain_events.ALL_EVENTS,
            from_block=from_block,
            to_block=to_block,
        )

        for event in returned_events:
            if event.get('args'):
                event['args'] = dict(event['args'])

        returned_events.sort(key=lambda evt: evt.get('block_number'), reverse=True)
        return returned_events

    def get_blockchain_events_channel(
            self,
            token_address: typing.TokenAddress,
            partner_address: typing.Address = None,
            from_block: typing.BlockSpecification = GENESIS_BLOCK_NUMBER,
            to_block: typing.BlockSpecification = 'latest',
    ):
        if not is_binary_address(token_address):
            raise InvalidAddress(
                'Expected binary address format for token in get_blockchain_events_channel',
            )
        token_network_address = self.raiden.default_registry.get_token_network(
            token_address,
        )
        if token_network_address is None:
            raise UnknownTokenAddress('Token address is not known.')

        channel_list = self.get_channel_list(
            registry_address=self.raiden.default_registry.address,
            token_address=token_address,
            partner_address=partner_address,
        )
        returned_events = []
        for channel in channel_list:
            returned_events.extend(
                blockchain_events.get_all_netting_channel_events(
                    chain=self.raiden.chain,
                    token_network_address=token_network_address,
                    netting_channel_identifier=channel.identifier,
                    contract_manager=self.raiden.contract_manager,
                    from_block=from_block,
                    to_block=to_block,
                ),
            )
        returned_events.sort(key=lambda evt: evt.get('block_number'), reverse=True)
        return returned_events

    def create_monitoring_request(
            self,
            balance_proof: BalanceProofSignedState,
            reward_amount: typing.TokenAmount,
    ) -> typing.Optional[RequestMonitoring]:
        """ This method can be used to create a `RequestMonitoring` message.
        It will contain all data necessary for an external monitoring service to
        - send an updateNonClosingBalanceProof transaction to the TokenNetwork contract,
        for the `balance_proof` that we received from a channel partner.
        - claim the `reward_amount` from the UDC.
        """
        # create RequestMonitoring message from the above + `reward_amount`
        monitor_request = RequestMonitoring.from_balance_proof_signed_state(
            balance_proof=balance_proof,
            reward_amount=reward_amount,
        )
        # sign RequestMonitoring and return
        monitor_request.sign(self.raiden.signer)
        return monitor_request

    def get_pending_transfers(
            self,
            token_address: typing.TokenAddress = None,
            partner_address: typing.Address = None,
    ) -> typing.List[typing.Dict[str, typing.Any]]:
        chain_state = views.state_from_raiden(self.raiden)
        transfer_tasks = views.get_all_transfer_tasks(chain_state)
        channel_id = None

        if token_address is not None:
            if self.raiden.default_registry.get_token_network(token_address) is None:
                raise UnknownTokenAddress(f'Token {token_address} not found.')
            if partner_address is not None:
                partner_channel = self.get_channel(
                    registry_address=self.raiden.default_registry.address,
                    token_address=token_address,
                    partner_address=partner_address,
                )
                channel_id = partner_channel.identifier

        return transfer_tasks_view(transfer_tasks, token_address, channel_id)
