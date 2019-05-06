from raiden.constants import EMPTY_HASH, EMPTY_MERKLE_ROOT
from raiden.network.proxies.token_network import ParticipantDetails, ParticipantsDetails
from raiden.raiden_event_handler import RaidenEventHandler
from raiden.tests.utils.factories import (
    make_32bytes,
    make_address,
    make_block_hash,
    make_canonical_identifier,
)
from raiden.tests.utils.mocks import make_raiden_service_mock
from raiden.transfer.events import ContractSendChannelBatchUnlock
from raiden.transfer.utils import hash_balance_data
from raiden.transfer.views import get_channelstate_by_token_network_and_partner, state_from_raiden


def test_handle_contract_send_channelunlock_already_unlocked():
    """This is a test for the scenario where the onchain unlock has
    already happened when we get to handle our own send unlock
    transaction.

    Regression test for https://github.com/raiden-network/raiden/issues/3152
    """
    channel_identifier = 1
    payment_network_identifier = make_address()
    token_network_identifier = make_address()
    participant = make_address()
    raiden = make_raiden_service_mock(
        payment_network_identifier=payment_network_identifier,
        token_network_identifier=token_network_identifier,
        channel_identifier=channel_identifier,
        partner=participant,
    )

    channel_state = get_channelstate_by_token_network_and_partner(
        chain_state=state_from_raiden(raiden),
        token_network_id=token_network_identifier,
        partner_address=participant,
    )

    channel_state.our_state.onchain_locksroot = EMPTY_MERKLE_ROOT
    channel_state.partner_state.onchain_locksroot = EMPTY_MERKLE_ROOT

    def detail_participants(  # pylint: disable=unused-argument
        participant1, participant2, block_identifier, channel_identifier
    ):
        transferred_amount = 1
        locked_amount = 1
        locksroot = make_32bytes()
        balance_hash = hash_balance_data(transferred_amount, locked_amount, locksroot)
        our_details = ParticipantDetails(
            address=raiden.address,
            deposit=5,
            withdrawn=0,
            is_closer=False,
            balance_hash=balance_hash,
            nonce=1,
            locksroot=locksroot,
            locked_amount=locked_amount,
        )

        transferred_amount = 1
        locked_amount = 1
        # Let's mock here that partner locksroot is 0x0
        balance_hash = hash_balance_data(transferred_amount, locked_amount, locksroot)
        partner_details = ParticipantDetails(
            address=participant,
            deposit=5,
            withdrawn=0,
            is_closer=True,
            balance_hash=balance_hash,
            nonce=1,
            locksroot=EMPTY_HASH,
            locked_amount=locked_amount,
        )
        return ParticipantsDetails(our_details, partner_details)

    # make sure detail_participants returns partner data with a locksroot of 0x0
    raiden.chain.token_network.detail_participants = detail_participants

    event = ContractSendChannelBatchUnlock(
        canonical_identifier=make_canonical_identifier(
            token_network_address=token_network_identifier, channel_identifier=channel_identifier
        ),
        participant=participant,
        triggered_by_block_hash=make_block_hash(),
    )

    # This should not throw an unrecoverable error
    RaidenEventHandler().on_raiden_event(
        raiden=raiden, chain_state=raiden.wal.state_manager.current_state, event=event
    )
