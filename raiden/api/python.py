from contextlib import ExitStack

import structlog
from eth_utils import is_binary_address, to_checksum_address

from raiden import waiting
from raiden.blockchain.events import (
    ALL_EVENTS,
    get_all_netting_channel_events,
    get_token_network_events,
    get_token_network_registry_events,
)
from raiden.transfer import views
from raiden.transfer.events import (
    EventPaymentSentSuccess,
    EventPaymentSentFailed,
    EventPaymentReceivedSuccess,
)
from raiden.transfer.state import NettingChannelState
from raiden.transfer.state_change import ActionChannelClose
from raiden.exceptions import (
    AlreadyRegisteredTokenAddress,
    ChannelNotFound,
    InsufficientFunds,
    InvalidAddress,
    InvalidAmount,
    InvalidSettleTimeout,
    UnknownTokenAddress,
    DepositOverLimit,
    DuplicatedChannelError,
    TokenNotRegistered,
    InsufficientGasReserve,
)
from raiden.settings import DEFAULT_RETRY_TIMEOUT
from raiden.utils import (
    pex,
    typing,
)
from raiden.utils.gas_reserve import has_enough_gas_reserve

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name

EVENTS_PAYMENT_HISTORY_RELATED = (
    EventPaymentSentSuccess,
    EventPaymentSentFailed,
    EventPaymentReceivedSuccess,
)


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

        try:
            registry = self.raiden.chain.token_network_registry(registry_address)

            return registry.add_token(token_address)
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
            views.state_from_raiden(self.raiden),
            payment_network_id=registry_address,
            token_address=token_address,
        )

        connection_manager = self.raiden.connection_manager_for_token_network(
            token_network_identifier,
        )

        has_enough_reserve, estimated_required_reserve = has_enough_gas_reserve(
            self.raiden,
            channels_to_open=initial_channel_target,
        )

        if not has_enough_reserve:
            raise InsufficientGasReserve((
                'The account balance is below the estimated amount necessary to '
                'finish the lifecycles of all active channels. A balance of at '
                f'least {estimated_required_reserve} wei is required.'
            ))

        connection_manager.connect(
            funds,
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
            views.state_from_raiden(self.raiden),
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
            reveal_timeout: typing.BlockTimeout = None,
            retry_timeout: typing.NetworkTimeout = DEFAULT_RETRY_TIMEOUT,
    ) -> typing.ChannelID:
        """ Open a channel with the peer at `partner_address`
        with the given `token_address`.
        """
        if reveal_timeout is None:
            reveal_timeout = self.raiden.config['reveal_timeout']

        if settle_timeout is None:
            settle_timeout = self.raiden.config['settle_timeout']

        if settle_timeout <= reveal_timeout:
            raise InvalidSettleTimeout(
                'reveal_timeout can not be larger-or-equal to settle_timeout',
            )

        if not is_binary_address(registry_address):
            raise InvalidAddress('Expected binary address format for registry in channel open')

        if not is_binary_address(token_address):
            raise InvalidAddress('Expected binary address format for token in channel open')

        if not is_binary_address(partner_address):
            raise InvalidAddress('Expected binary address format for partner in channel open')

        chain_state = views.state_from_raiden(self.raiden)
        channel_state = views.get_channelstate_for(
            chain_state,
            registry_address,
            token_address,
            partner_address,
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
                partner_address,
                settle_timeout,
            )
        except DuplicatedChannelError:
            log.info('partner opened channel first')

        waiting.wait_for_newchannel(
            self.raiden,
            registry_address,
            token_address,
            partner_address,
            retry_timeout,
        )
        chain_state = views.state_from_raiden(self.raiden)
        channel_state = views.get_channelstate_for(
            chain_state,
            registry_address,
            token_address,
            partner_address,
        )

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

        token_networks = views.get_token_network_addresses_for(
            chain_state,
            registry_address,
        )
        channel_state = views.get_channelstate_for(
            chain_state,
            registry_address,
            token_address,
            partner_address,
        )

        if not is_binary_address(token_address):
            raise InvalidAddress('Expected binary address format for token in channel deposit')

        if not is_binary_address(partner_address):
            raise InvalidAddress('Expected binary address format for partner in channel deposit')

        if token_address not in token_networks:
            raise UnknownTokenAddress('Unknown token address')

        if channel_state is None:
            raise InvalidAddress('No channel with partner_address for the given token')

        token = self.raiden.chain.token(token_address)
        netcontract_address = channel_state.identifier
        token_network_registry = self.raiden.chain.token_network_registry(registry_address)
        token_network_address = token_network_registry.get_token_network(token_address)
        token_network_proxy = self.raiden.chain.token_network(token_network_address)
        channel_proxy = self.raiden.chain.payment_channel(
            token_network_proxy.address,
            netcontract_address,
        )

        balance = token.balance_of(self.raiden.address)

        deposit_limit = token_network_proxy.proxy.contract.functions.deposit_limit().call()
        if total_deposit > deposit_limit:
            raise DepositOverLimit(
                'The deposit of {} is bigger than the current limit of {}'.format(
                    total_deposit,
                    deposit_limit,
                ),
            )

        if total_deposit <= channel_state.our_state.contract_balance:
            # no action required
            return

        addendum = total_deposit - channel_state.our_state.contract_balance

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

        # If concurrent operations are happening on the channel, fail the request
        with channel_proxy.lock_or_raise():
            # set_total_deposit calls approve
            # token.approve(netcontract_address, addendum)
            channel_proxy.set_total_deposit(total_deposit)

            target_address = self.raiden.address
            waiting.wait_for_participant_newbalance(
                self.raiden,
                registry_address,
                token_address,
                partner_address,
                target_address,
                total_deposit,
                retry_timeout,
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
            registry_address,
            token_address,
            [partner_address],
            retry_timeout,
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

        valid_tokens = views.get_token_network_addresses_for(
            views.state_from_raiden(self.raiden),
            registry_address,
        )
        if token_address not in valid_tokens:
            raise UnknownTokenAddress('Token address is not known.')

        chain_state = views.state_from_raiden(self.raiden)
        channels_to_close = views.filter_channels_by_partneraddress(
            chain_state,
            registry_address,
            token_address,
            partner_addresses,
        )
        token_network_identifier = views.get_token_network_identifier_by_token_address(
            views.state_from_raiden(self.raiden),
            registry_address,
            token_address,
        )

        # If concurrent operations are happening on one of the channels, fail entire
        # request.
        with ExitStack() as stack:
            # Put all the locks in this outer context so that the netting channel functions
            # don't release the locks when their context goes out of scope
            for channel_state in channels_to_close:
                channel = self.raiden.chain.payment_channel(
                    token_network_identifier,
                    channel_state.identifier,
                )
                stack.enter_context(channel.lock_or_raise())

            for channel_state in channels_to_close:
                channel_close = ActionChannelClose(
                    token_network_identifier,
                    channel_state.identifier,
                )

                self.raiden.handle_state_change(channel_close)

            channel_ids = [channel_state.identifier for channel_state in channels_to_close]

            waiting.wait_for_close(
                self.raiden,
                registry_address,
                token_address,
                channel_ids,
                retry_timeout,
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

        if partner_address and not is_binary_address(partner_address):
            raise InvalidAddress('Expected binary address format for partner in get_channel_list')

        result = list()
        if token_address and partner_address:
            channel_state = views.get_channelstate_for(
                views.state_from_raiden(self.raiden),
                registry_address,
                token_address,
                partner_address,
            )

            if channel_state:
                result = [channel_state]
            else:
                result = []

        elif token_address:
            result = views.list_channelstate_for_tokennetwork(
                views.state_from_raiden(self.raiden),
                registry_address,
                token_address,
            )

        elif partner_address:
            result = views.list_channelstate_for_tokennetwork(
                views.state_from_raiden(self.raiden),
                registry_address,
                partner_address,
            )

        else:
            result = views.list_all_channelstate(
                views.state_from_raiden(self.raiden),
            )

        return result

    def get_node_network_state(self, node_address: typing.Address):
        """ Returns the currently network status of `node_address`. """
        return views.get_node_network_status(
            views.state_from_raiden(self.raiden),
            node_address,
        )

    def start_health_check_for(self, node_address: typing.Address):
        """ Returns the currently network status of `node_address`. """
        self.raiden.start_health_check_for(node_address)

    def get_tokens_list(self, registry_address: typing.PaymentNetworkID):
        """Returns a list of tokens the node knows about"""
        tokens_list = views.get_token_network_addresses_for(
            views.state_from_raiden(self.raiden),
            registry_address,
        )
        return tokens_list

    def transfer_and_wait(
            self,
            registry_address: typing.PaymentNetworkID,
            token_address: typing.TokenAddress,
            amount: typing.TokenAmount,
            target: typing.Address,
            identifier: int = None,
            transfer_timeout: int = None,
    ):
        """ Do a transfer with `target` with the given `amount` of `token_address`. """
        # pylint: disable=too-many-arguments

        async_result = self.transfer_async(
            registry_address,
            token_address,
            amount,
            target,
            identifier,
        )
        return async_result.wait(timeout=transfer_timeout)

    def transfer_async(
            self,
            registry_address: typing.PaymentNetworkID,
            token_address: typing.TokenAddress,
            amount: typing.TokenAmount,
            target: typing.Address,
            identifier: int = None,
    ):

        if not isinstance(amount, int):
            raise InvalidAmount('Amount not a number')

        if amount <= 0:
            raise InvalidAmount('Amount negative')

        if not is_binary_address(token_address):
            raise InvalidAddress('token address is not valid.')

        if not is_binary_address(target):
            raise InvalidAddress('target address is not valid.')

        valid_tokens = views.get_token_network_addresses_for(
            views.state_from_raiden(self.raiden),
            registry_address,
        )
        if token_address not in valid_tokens:
            raise UnknownTokenAddress('Token address is not known.')

        log.debug(
            'initiating transfer',
            initiator=pex(self.raiden.address),
            target=pex(target),
            token=pex(token_address),
            amount=amount,
            identifier=identifier,
        )

        payment_network_identifier = self.raiden.default_registry.address
        token_network_identifier = views.get_token_network_identifier_by_token_address(
            views.state_from_raiden(self.raiden),
            payment_network_identifier,
            token_address,
        )
        async_result = self.raiden.mediated_transfer_async(
            token_network_identifier,
            amount,
            target,
            identifier,
        )
        return async_result

    def get_network_events(
            self, registry_address: typing.PaymentNetworkID,
            from_block: typing.BlockSpecification = 0,
            to_block: typing.BlockSpecification = 'latest',
    ):
        return sorted(get_token_network_registry_events(
            self.raiden.chain,
            registry_address,
            events=ALL_EVENTS,
            from_block=from_block,
            to_block=to_block,
        ), key=lambda evt: evt.get('block_number'), reverse=True)

    def get_payment_history(
            self,
            from_block: typing.BlockSpecification = 0,
            to_block: typing.BlockSpecification = 'latest',
    ):
        raiden_events = self.raiden.wal.storage.get_events_by_block(
            from_block=from_block,
            to_block=to_block,
        )

        # filtering only for externally visible events
        events = [
            (block_number, event)
            for block_number, event in raiden_events
            if isinstance(event, EVENTS_PAYMENT_HISTORY_RELATED)
        ]

        events.sort(key=lambda event: event[0], reverse=True)
        return events

    def get_payment_history_for_token(
            self,
            token_address: typing.TokenAddress,
            from_block: typing.BlockSpecification = 0,
            to_block: typing.BlockSpecification = 'latest',
    ):
        if not is_binary_address(token_address):
            raise InvalidAddress(
                'Expected binary address format for token in get_token_network_events',
            )

        raiden_events = self.get_payment_history(
            from_block=from_block,
            to_block=to_block,
        )

        events = []
        if len(raiden_events) > 0:
            event_tuple = raiden_events[0]
            event_data = event_tuple[1]
            token_network_identifier = views.get_token_network_identifier_by_token_address(
                views.state_from_raiden(self.raiden),
                event_data.payment_network_identifier,
                token_address,
            )

            # filtering for the events which have the same token network identifier
            events = [
                (block_number, event)
                for block_number, event in raiden_events
                if token_network_identifier == event.token_network_identifier
            ]

        return events

    def get_payment_history_for_token_and_target(
            self,
            token_address: typing.TokenAddress,
            target_address: typing.Address,
            from_block: typing.BlockSpecification = 0,
            to_block: typing.BlockSpecification = 'latest',
    ):
        if target_address and not is_binary_address(target_address):
            raise InvalidAddress(
                'Expected binary address format for '
                'target_address in get_payment_history_partner',
            )

        raiden_events = self.get_payment_history_for_token(
            token_address=token_address,
            from_block=from_block,
            to_block=to_block,
        )

        events = [
            (block_number, event)
            for block_number, event in raiden_events
            if (hasattr(event, 'target') and event.target == target_address) or
               (hasattr(event, 'initiator') and event.initiator == target_address)
        ]

        return events

    def get_channel_events_blockchain(
            self,
            token_address: typing.TokenAddress,
            partner_address: typing.Address = None,
            from_block: typing.BlockSpecification = 0,
            to_block: typing.BlockSpecification = 'latest',
    ):
        if not is_binary_address(token_address):
            raise InvalidAddress(
                'Expected binary address format for token in get_token_network_events_blockchain',
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
            returned_events.extend(get_all_netting_channel_events(
                self.raiden.chain,
                token_network_address,
                channel.identifier,
                from_block=from_block,
                to_block=to_block,
            ))
        returned_events.sort(key=lambda evt: evt.get('block_number'), reverse=True)
        return returned_events

    def get_channel_events_raiden(
            self,
            token_address: typing.TokenAddress,
            partner_address: typing.Address = None,
            from_block: typing.BlockSpecification = 0,
            to_block: typing.BlockSpecification = 'latest',
    ):

        if not is_binary_address(token_address):
            raise InvalidAddress(
                'Expected binary address format for token in get_token_network_events_blockchain',
            )

        returned_events = []
        raiden_events = self.raiden.wal.storage.get_events_by_block(
            from_block=from_block,
            to_block=to_block,
        )
        # Here choose which raiden internal events we want to expose to the end user
        for block_number, event in raiden_events:
            new_event = {
                'block_number': block_number,
                'event': type(event).__name__,
            }
            if partner_address:
                if hasattr(event, 'recipient') and event.recipient == partner_address:
                    if hasattr(event, 'transfer') and event.transfer.token == token_address:
                        event.transfer = repr(event.transfer)
                    elif hasattr(event, 'token') and event.token == token_address:
                        event.balance_proof = repr(event.balance_proof)

            else:
                if hasattr(event, 'transfer') and event.transfer.token == token_address:
                    event.transfer = repr(event.transfer)
                elif hasattr(event, 'token') and event.token == token_address:
                    event.balance_proof = repr(event.balance_proof)
            new_event.update(event.__dict__)
            returned_events.append(new_event)

        returned_events.sort(key=lambda evt: evt.get('block_number'), reverse=True)
        return returned_events

    def get_token_network_events_blockchain(
            self,
            token_address: typing.TokenAddress,
            from_block: typing.BlockSpecification = 0,
            to_block: typing.BlockSpecification = 'latest',
    ):
        """Returns a list of blockchain events coresponding to the token_address."""

        if not is_binary_address(token_address):
            raise InvalidAddress(
                'Expected binary address format for token in get_token_network_events_blockchain',
            )
        token_network_address = self.raiden.default_registry.get_token_network(
            token_address,
        )

        if token_network_address is None:
            raise UnknownTokenAddress('Token address is not known.')

        returned_events = get_token_network_events(
            self.raiden.chain,
            token_network_address,
            events=ALL_EVENTS,
            from_block=from_block,
            to_block=to_block,
        )

        for event in returned_events:
            if event.get('args'):
                event['args'] = dict(event['args'])

        returned_events.sort(key=lambda evt: evt.get('block_number'), reverse=True)
        return returned_events

    def get_token_network_events_raiden(
            self,
            token_address,
            from_block,
            to_block='latest',
    ):
        """Returns a list of internal events coresponding to the token_address."""
        if not is_binary_address(token_address):
            raise InvalidAddress(
                'Expected binary address format for token in get_token_network_events_blockchain',
            )

        returned_events = []
        raiden_events = self.raiden.wal.storage.get_events_by_block(
            from_block=from_block,
            to_block=to_block,
        )

        for block_number, event in raiden_events:
            new_event = {
                'block_number': block_number,
                'event': type(event).__name__,
            }
            if hasattr(event, 'transfer'):
                if event.transfer.token == token_address:
                    event.transfer = repr(event.transfer)
            elif hasattr(event, 'token'):
                if event.token == token_address:
                    event.balance_proof = repr(event.balance_proof)
            new_event.update(event.__dict__)
            returned_events.append(new_event)
        returned_events.sort(key=lambda evt: evt.get('block_number'), reverse=True)
        return returned_events

    transfer = transfer_and_wait
