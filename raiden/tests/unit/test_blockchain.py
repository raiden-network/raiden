# pylint: disable=no-member
import pytest

from raiden.blockchain.state import create_channel_state_from_blockchain_data
from raiden.network.proxies.token_network import (
    ChannelData,
    ChannelDetails,
    ParticipantDetails,
    ParticipantsDetails,
)
from raiden.tests.utils import factories
from raiden.transfer import channel
from raiden.transfer.state import (
    CHANNEL_STATE_CLOSED,
    CHANNEL_STATE_OPENED,
    TransactionExecutionStatus,
)


def participant_details(address):
    return ParticipantDetails(
        address=address,
        deposit=100,
        withdrawn=0,
        is_closer=False,
        balance_hash=None,
        nonce=1,
        locksroot=factories.EMPTY_MERKLE_ROOT,
        locked_amount=0,
    )


@pytest.fixture
def participants_data() -> ParticipantsDetails:
    return ParticipantsDetails(
        our_details=participant_details(factories.HOP1),
        partner_details=participant_details(factories.HOP2),
    )


@pytest.fixture
def channel_data() -> ChannelData:
    return ChannelData(
        channel_identifier=factories.UNIT_CHANNEL_ID,
        settle_block_number=None,
        state=factories.create(factories.NettingChannelStateProperties()),
    )


@pytest.fixture
def channel_details(channel_data, participants_data) -> ChannelDetails:
    return ChannelDetails(
        chain_id=factories.UNIT_CHAIN_ID,
        channel_data=channel_data,
        participants_data=participants_data,
    )


@pytest.fixture
def params(channel_details):
    return dict(
        payment_network_address=factories.UNIT_PAYMENT_NETWORK_IDENTIFIER,
        token_network_address=factories.UNIT_TOKEN_NETWORK_ADDRESS,
        token_address=factories.UNIT_TOKEN_ADDRESS,
        channel_details=channel_details,
        identifier=factories.UNIT_CHANNEL_ID,
        reveal_timeout=factories.UNIT_REVEAL_TIMEOUT,
        settle_timeout=factories.UNIT_SETTLE_TIMEOUT,
        opened_block_number=10,
        closed_block_number=None,
    )


def test_create_channel_state_from_blockchain_data_invalid_opened_block(params):
    """ Nonpositive block numbers for the opening of the channel should be ignored. """
    params.pop("opened_block_number")
    assert create_channel_state_from_blockchain_data(opened_block_number=0, **params) is None
    assert create_channel_state_from_blockchain_data(opened_block_number=-5, **params) is None


def test_create_channel_state_from_blockchain_data(params, participants_data):
    channel_state = create_channel_state_from_blockchain_data(**params)

    assert channel_state.payment_network_address == params["payment_network_address"]
    assert channel_state.token_network_address == params["token_network_address"]
    assert channel_state.token_address == params["token_address"]
    assert channel_state.reveal_timeout == params["reveal_timeout"]
    assert channel_state.settle_timeout == params["settle_timeout"]

    assert channel_state.canonical_identifier.channel_identifier == params["identifier"]
    assert channel_state.our_state.address == participants_data.our_details.address
    assert channel_state.partner_state.address == participants_data.partner_details.address

    assert channel.get_status(channel_state) == CHANNEL_STATE_OPENED
    assert channel_state.open_transaction.finished_block_number == params["opened_block_number"]
    assert channel_state.open_transaction.result == TransactionExecutionStatus.SUCCESS
    assert channel_state.close_transaction is None
    assert channel_state.settle_transaction is None


def test_create_channel_state_from_blockchain_data_for_closed_channel(params):
    params["closed_block_number"] = 12
    channel_state = create_channel_state_from_blockchain_data(**params)

    assert channel.get_status(channel_state) == CHANNEL_STATE_CLOSED
    assert channel_state.open_transaction.finished_block_number == params["opened_block_number"]
    assert channel_state.open_transaction.result == TransactionExecutionStatus.SUCCESS
    assert channel_state.close_transaction.finished_block_number == params["closed_block_number"]
    assert channel_state.close_transaction.result == TransactionExecutionStatus.SUCCESS
    assert channel_state.settle_transaction is None
