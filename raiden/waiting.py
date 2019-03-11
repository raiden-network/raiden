import gevent
import structlog
from web3 import Web3

from raiden.transfer import channel, views
from raiden.transfer.events import EventPaymentReceivedSuccess
from raiden.transfer.state import (
    CHANNEL_AFTER_CLOSE_STATES,
    CHANNEL_STATE_SETTLED,
    NODE_NETWORK_REACHABLE,
)
from raiden.utils import CanonicalIdentifier, typing

# type alias to avoid both circular dependencies and flake8 errors
RaidenService = 'RaidenService'

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name


def wait_for_block(
        raiden: RaidenService,
        block_number: typing.BlockNumber,
        retry_timeout: float,
) -> None:
    while raiden.get_block_number() < block_number:
        gevent.sleep(retry_timeout)


def wait_for_block_using_web3(
        web3: Web3,
        block_number: typing.BlockNumber,
        retry_timout: float,
) -> None:
    while web3.eth.blockNumber < block_number:
        gevent.sleep(retry_timout)


def wait_for_newchannel(
        raiden: RaidenService,
        payment_network_id: typing.PaymentNetworkID,
        token_address: typing.TokenAddress,
        partner_address: typing.Address,
        retry_timeout: float,
) -> None:
    """Wait until the channel with partner_address is registered.

    Note:
        This does not time out, use gevent.Timeout.
    """
    channel_state = views.get_channelstate_for(
        views.state_from_raiden(raiden),
        payment_network_id,
        token_address,
        partner_address,
    )

    while channel_state is None:
        gevent.sleep(retry_timeout)
        channel_state = views.get_channelstate_for(
            views.state_from_raiden(raiden),
            payment_network_id,
            token_address,
            partner_address,
        )


def wait_for_participant_newbalance(
        raiden: RaidenService,
        payment_network_id: typing.PaymentNetworkID,
        token_address: typing.TokenAddress,
        partner_address: typing.Address,
        target_address: typing.Address,
        target_balance: typing.TokenAmount,
        retry_timeout: float,
) -> None:
    """Wait until a given channels balance exceeds the target balance.

    Note:
        This does not time out, use gevent.Timeout.
    """
    if target_address == raiden.address:
        balance = lambda channel_state: channel_state.our_state.contract_balance
    elif target_address == partner_address:
        balance = lambda channel_state: channel_state.partner_state.contract_balance
    else:
        raise ValueError('target_address must be one of the channel participants')

    channel_state = views.get_channelstate_for(
        views.state_from_raiden(raiden),
        payment_network_id,
        token_address,
        partner_address,
    )

    while balance(channel_state) < target_balance:
        gevent.sleep(retry_timeout)
        channel_state = views.get_channelstate_for(
            views.state_from_raiden(raiden),
            payment_network_id,
            token_address,
            partner_address,
        )


def wait_for_payment_balance(
        raiden: RaidenService,
        payment_network_id: typing.PaymentNetworkID,
        token_address: typing.TokenAddress,
        partner_address: typing.Address,
        target_address: typing.Address,
        target_balance: typing.TokenAmount,
        retry_timeout: float,
) -> None:
    """Wait until a given channel's balance exceeds the target balance.

    Note:
        This does not time out, use gevent.Timeout.
    """
    def get_balance(end_state):
        if end_state.balance_proof:
            return end_state.balance_proof.transferred_amount
        else:
            return 0

    if target_address == raiden.address:
        balance = lambda channel_state: get_balance(channel_state.partner_state)
    elif target_address == partner_address:
        balance = lambda channel_state: get_balance(channel_state.our_state)
    else:
        raise ValueError('target_address must be one of the channel participants')

    channel_state = views.get_channelstate_for(
        views.state_from_raiden(raiden),
        payment_network_id,
        token_address,
        partner_address,
    )

    while balance(channel_state) < target_balance:
        log.critical('wait', b=balance(channel_state), t=target_balance)
        gevent.sleep(retry_timeout)
        channel_state = views.get_channelstate_for(
            views.state_from_raiden(raiden),
            payment_network_id,
            token_address,
            partner_address,
        )


def wait_for_channel_in_states(
        raiden: RaidenService,
        payment_network_id: typing.PaymentNetworkID,
        token_address: typing.TokenAddress,
        channel_ids: typing.List[typing.ChannelID],
        retry_timeout: float,
        target_states: typing.Tuple[str],
) -> None:
    """Wait until all channels are in `target_states`.

    Note:
        This does not time out, use gevent.Timeout.
    """
    channel_ids = list(channel_ids)

    while channel_ids:
        last_id = channel_ids[-1]
        chain_state = views.state_from_raiden(raiden)
        token_network_address = views.get_token_network_by_token_address(
            chain_state=chain_state,
            payment_network_id=payment_network_id,
            token_address=token_address,
        ).address
        assert token_network_address
        channel_state = views.get_channelstate_by_canonical_identifier(
            chain_state=chain_state,
            canonical_identifier=CanonicalIdentifier(
                chain_identifier=chain_state.chain_id,
                token_network_address=token_network_address,
                channel_identifier=last_id,
            ),
        )

        channel_is_settled = (
            channel_state is None or
            channel.get_status(channel_state) in target_states
        )

        if channel_is_settled:
            channel_ids.pop()
        else:
            gevent.sleep(retry_timeout)


def wait_for_close(
        raiden: RaidenService,
        payment_network_id: typing.PaymentNetworkID,
        token_address: typing.TokenAddress,
        channel_ids: typing.List[typing.ChannelID],
        retry_timeout: float,
) -> None:
    """Wait until all channels are closed.

    Note:
        This does not time out, use gevent.Timeout.
    """
    return wait_for_channel_in_states(
        raiden=raiden,
        payment_network_id=payment_network_id,
        token_address=token_address,
        channel_ids=channel_ids,
        retry_timeout=retry_timeout,
        target_states=CHANNEL_AFTER_CLOSE_STATES,
    )


def wait_for_payment_network(
        raiden: RaidenService,
        payment_network_id: typing.PaymentNetworkID,
        token_address: typing.TokenAddress,
        retry_timeout: float,
) -> None:
    token_network = views.get_token_network_by_token_address(
        views.state_from_raiden(raiden),
        payment_network_id,
        token_address,
    )
    while token_network is None:
        gevent.sleep(retry_timeout)
        token_network = views.get_token_network_by_token_address(
            views.state_from_raiden(raiden),
            payment_network_id,
            token_address,
        )


def wait_for_settle(
        raiden: RaidenService,
        payment_network_id: typing.PaymentNetworkID,
        token_address: typing.TokenAddress,
        channel_ids: typing.List[typing.ChannelID],
        retry_timeout: float,
) -> None:
    """Wait until all channels are settled.

    Note:
        This does not time out, use gevent.Timeout.
    """
    return wait_for_channel_in_states(
        raiden=raiden,
        payment_network_id=payment_network_id,
        token_address=token_address,
        channel_ids=channel_ids,
        retry_timeout=retry_timeout,
        target_states=(CHANNEL_STATE_SETTLED,),
    )


def wait_for_settle_all_channels(
        raiden: RaidenService,
        retry_timeout: float,
) -> None:
    """Wait until all channels are settled.

    Note:
        This does not time out, use gevent.Timeout.
    """
    chain_state = views.state_from_raiden(raiden)

    id_paymentnetworkstate = chain_state.identifiers_to_paymentnetworks.items()
    for payment_network_id, payment_network_state in id_paymentnetworkstate:

        id_tokennetworkstate = payment_network_state.tokenidentifiers_to_tokennetworks.items()
        for token_network_id, token_network_state in id_tokennetworkstate:
            channel_ids = token_network_state.channelidentifiers_to_channels.keys()

            wait_for_settle(
                raiden,
                payment_network_id,
                token_network_id,
                channel_ids,
                retry_timeout,
            )


def wait_for_healthy(
        raiden: RaidenService,
        node_address: typing.Address,
        retry_timeout: float,
) -> None:
    """Wait until `node_address` becomes healthy.

    Note:
        This does not time out, use gevent.Timeout.
    """
    network_statuses = views.get_networkstatuses(
        views.state_from_raiden(raiden),
    )

    while network_statuses.get(node_address) != NODE_NETWORK_REACHABLE:
        gevent.sleep(retry_timeout)
        network_statuses = views.get_networkstatuses(
            views.state_from_raiden(raiden),
        )


def wait_for_transfer_success(
        raiden: RaidenService,
        payment_identifier: typing.PaymentID,
        amount: typing.PaymentAmount,
        retry_timeout: float,
) -> None:
    """Wait until a transfer with a specific identifier and amount
    is seen in the WAL.

    Note:
        This does not time out, use gevent.Timeout.
    """
    found = False
    while not found:
        state_events = raiden.wal.storage.get_events()
        for event in state_events:
            found = (
                isinstance(event, EventPaymentReceivedSuccess) and
                event.identifier == payment_identifier and
                event.amount == amount
            )
            if found:
                break

        gevent.sleep(retry_timeout)
