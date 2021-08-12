from raiden.tests.utils import factories
from raiden.transfer import views
from raiden.transfer.mediated_transfer.state import InitiatorPaymentState
from raiden.transfer.mediated_transfer.tasks import InitiatorTask
from raiden.transfer.state import (
    TokenNetworkRegistryState,
    TokenNetworkState,
    TransactionExecutionStatus,
)
from raiden.transfer.views import (
    filter_channels_by_partneraddress,
    filter_channels_by_status,
    get_networks,
    get_participants_addresses,
    get_token_identifiers,
    get_token_network_addresses,
    get_token_network_registry_by_token_network_address,
    get_transfer_secret,
)
from raiden.utils.copy import deepcopy


def test_filter_channels_by_partneraddress_empty(chain_state):
    token_network_registry_address = factories.make_address()
    token_address = factories.make_address()
    partner_addresses = [factories.make_address(), factories.make_address()]
    assert (
        filter_channels_by_partneraddress(
            chain_state=chain_state,
            token_network_registry_address=token_network_registry_address,
            token_address=token_address,
            partner_addresses=partner_addresses,
        )
        == []
    )


def test_filter_channels_by_status_empty_excludes():
    channel_states = factories.make_channel_set(number_of_channels=3).channels
    channel_states[1].close_transaction = TransactionExecutionStatus(
        started_block_number=channel_states[1].open_transaction.started_block_number,
        finished_block_number=channel_states[1].open_transaction.finished_block_number,
        result=TransactionExecutionStatus.SUCCESS,
    )
    channel_states[2].close_transaction = TransactionExecutionStatus(
        started_block_number=channel_states[2].open_transaction.started_block_number,
        finished_block_number=channel_states[2].open_transaction.finished_block_number,
        result=TransactionExecutionStatus.SUCCESS,
    )
    channel_states[2].settle_transaction = channel_states[2].close_transaction
    assert (
        filter_channels_by_status(channel_states=channel_states, exclude_states=None)
        == channel_states
    )


def test_get_participants_addresses_no_token_network(chain_state):
    assert (
        get_participants_addresses(
            chain_state=chain_state,
            token_network_registry_address=factories.make_address(),
            token_address=factories.make_address(),
        )
        == set()
    )


def test_get_token_network_registry_by_token_network_address_is_none(chain_state):
    assert (
        get_token_network_registry_by_token_network_address(
            chain_state=chain_state, token_network_address=factories.make_address()
        )
        is None
    )


def test_get_token_network_addresses_empty_list_for_token_network_registry_none(chain_state):
    assert (
        get_token_network_addresses(
            chain_state=chain_state, token_network_registry_address=factories.make_address()
        )
        == []
    )


def test_token_identifiers_empty_list_for_token_network_registry_none(chain_state):
    assert (
        get_token_identifiers(
            chain_state=chain_state, token_network_registry_address=factories.make_address()
        )
        == []
    )


def test_get_transfer_secret_none_for_none_transfer_state(chain_state):
    secret = factories.make_secret()
    transfer = factories.create(factories.LockedTransferUnsignedStateProperties(secret=secret))
    secrethash = transfer.lock.secrethash
    payment_state = InitiatorPaymentState(initiator_transfers={secrethash: None}, routes=[])
    task = InitiatorTask(
        token_network_address=factories.UNIT_TOKEN_NETWORK_ADDRESS, manager_state=payment_state
    )
    chain_state.payment_mapping.secrethashes_to_task[secrethash] = task
    assert get_transfer_secret(chain_state=chain_state, secrethash=secrethash) is None


def test_channelstate_filters():
    test_state = factories.make_chain_state(number_of_channels=5)
    chain_state = test_state.chain_state
    token_network_registry_address = test_state.token_network_registry_address
    token_address = test_state.token_address

    (
        channel_open,
        channel_closing,
        channel_closed,
        channel_settling,
        channel_settled,
    ) = test_state.channels
    in_progress = TransactionExecutionStatus(started_block_number=chain_state.block_number)
    done = TransactionExecutionStatus(
        started_block_number=chain_state.block_number,
        finished_block_number=chain_state.block_number,
        result=TransactionExecutionStatus.SUCCESS,
    )
    channel_closing.close_transaction = in_progress
    channel_closed.close_transaction = done
    channel_settling.close_transaction = done
    channel_settling.settle_transaction = in_progress
    channel_settled.close_transaction = done
    channel_settled.settle_transaction = done

    unknown_token = factories.make_address()
    assert (
        views.get_channelstate_open(
            chain_state=chain_state,
            token_network_registry_address=token_network_registry_address,
            token_address=unknown_token,
        )
        == []
    )

    opened = views.get_channelstate_open(
        chain_state=chain_state,
        token_network_registry_address=token_network_registry_address,
        token_address=token_address,
    )
    assert opened == [channel_open]

    closing = views.get_channelstate_closing(
        chain_state=chain_state,
        token_network_registry_address=token_network_registry_address,
        token_address=token_address,
    )
    assert closing == [channel_closing]

    closed = views.get_channelstate_closed(
        chain_state=chain_state,
        token_network_registry_address=token_network_registry_address,
        token_address=token_address,
    )
    assert closed == [channel_closed]

    settling = views.get_channelstate_settling(
        chain_state=chain_state,
        token_network_registry_address=token_network_registry_address,
        token_address=token_address,
    )
    assert settling == [channel_settling]

    settled = views.get_channelstate_settled(
        chain_state=chain_state,
        token_network_registry_address=token_network_registry_address,
        token_address=token_address,
    )
    assert settled == [channel_settled]


def test_list_all_channelstate():
    test_state = factories.make_chain_state(number_of_channels=3)
    assert sorted(
        channel.partner_state.address
        for channel in views.list_all_channelstate(test_state.chain_state)
    ) == sorted(channel.partner_state.address for channel in test_state.channels)


def test_get_our_capacity_for_token_network():
    test_state = factories.make_chain_state(number_of_channels=3)
    chain_state = test_state.chain_state
    test_state.channels[-1].close_transaction = TransactionExecutionStatus(
        started_block_number=chain_state.block_number,
        finished_block_number=chain_state.block_number,
        result=TransactionExecutionStatus.SUCCESS,
    )
    expected_sum = sum(c.our_state.contract_balance for c in test_state.channels[:-1])
    assert (
        views.get_our_deposits_for_token_network(
            chain_state=chain_state,
            token_network_registry_address=test_state.token_network_registry_address,
            token_address=test_state.token_address,
        )
        == expected_sum
    )


def test_get_token_network_by_address():
    test_state = factories.make_chain_state(number_of_channels=3)
    assert (
        views.get_token_network_by_address(
            test_state.chain_state, test_state.token_network_address
        ).address
        == test_state.token_network_address
    )
    unknown_token_network_address = factories.make_address()
    assert (
        views.get_token_network_by_address(test_state.chain_state, unknown_token_network_address)
        is None
    )


def test_get_channelstate_for():
    test_state = factories.make_chain_state(number_of_channels=3)
    partner_address = test_state.channels[1].partner_state.address
    assert (
        views.get_channelstate_for(
            chain_state=test_state.chain_state,
            token_network_registry_address=test_state.token_network_registry_address,
            token_address=test_state.token_address,
            partner_address=partner_address,
        )
        == test_state.channels[1]
    )


def test_get_channelstate_by_token_network_and_partner():
    test_state = factories.make_chain_state(number_of_channels=3)
    partner_address = test_state.channels[1].partner_state.address
    assert (
        views.get_channelstate_by_token_network_and_partner(
            chain_state=test_state.chain_state,
            token_network_address=test_state.token_network_address,
            partner_address=partner_address,
        )
        == test_state.channels[1]
    )


def test_get_channelstate_by_canonical_identifier():
    test_state = factories.make_chain_state(number_of_channels=3)
    canonical_identifier = test_state.channels[1].canonical_identifier

    assert (
        views.get_channelstate_by_canonical_identifier(
            chain_state=test_state.chain_state, canonical_identifier=canonical_identifier
        )
        == test_state.channels[1]
    )


def test_filter_channels_by_partneraddress():
    test_state = factories.make_chain_state(number_of_channels=3)
    partner_addresses = [c.partner_state.address for c in test_state.channels[1:]]

    assert (
        views.filter_channels_by_partneraddress(
            chain_state=test_state.chain_state,
            token_network_registry_address=test_state.token_network_registry_address,
            token_address=test_state.token_address,
            partner_addresses=partner_addresses,
        )
        == test_state.channels[1:]
    )


def test_total_token_network_channels():
    number_of_channels = 3
    test_state = factories.make_chain_state(number_of_channels=number_of_channels)
    unknown_token_address = factories.make_address()
    unknown_token_network_registry_address = factories.make_address()
    assert (
        views.total_token_network_channels(
            chain_state=test_state.chain_state,
            token_network_registry_address=unknown_token_network_registry_address,
            token_address=unknown_token_address,
        )
        == 0
    )
    assert (
        views.total_token_network_channels(
            chain_state=test_state.chain_state,
            token_network_registry_address=unknown_token_network_registry_address,
            token_address=test_state.token_address,
        )
        == 0
    )
    assert (
        views.total_token_network_channels(
            chain_state=test_state.chain_state,
            token_network_registry_address=test_state.token_network_registry_address,
            token_address=unknown_token_address,
        )
        == 0
    )
    assert (
        views.total_token_network_channels(
            chain_state=test_state.chain_state,
            token_network_registry_address=test_state.token_network_registry_address,
            token_address=test_state.token_address,
        )
        == number_of_channels
    )


def test_get_token_network_registry_by_token_network_address():
    test_state = factories.make_chain_state(number_of_channels=1)
    assert (
        views.get_token_network_registry_by_token_network_address(
            chain_state=test_state.chain_state, token_network_address=factories.make_address()
        )
        is None
    )
    assert (
        views.get_token_network_registry_by_token_network_address(
            chain_state=test_state.chain_state, token_network_address=test_state.token_address
        )
        is None
    )
    assert (
        views.get_token_network_registry_by_token_network_address(
            chain_state=test_state.chain_state,
            token_network_address=test_state.token_network_address,
        ).address
        == test_state.token_network_registry_address
    )


def test_get_token_network_address_by_token_address():
    test_state = factories.make_chain_state(number_of_channels=1)
    assert (
        views.get_token_network_address_by_token_address(
            chain_state=test_state.chain_state,
            token_network_registry_address=factories.make_address(),
            token_address=factories.make_address(),
        )
        is None
    )
    assert (
        views.get_token_network_address_by_token_address(
            chain_state=test_state.chain_state,
            token_network_registry_address=test_state.token_network_registry_address,
            token_address=factories.make_address(),
        )
        is None
    )
    assert (
        views.get_token_network_address_by_token_address(
            chain_state=test_state.chain_state,
            token_network_registry_address=factories.make_address(),
            token_address=test_state.token_address,
        )
        is None
    )
    assert (
        views.get_token_network_address_by_token_address(
            chain_state=test_state.chain_state,
            token_network_registry_address=test_state.token_network_registry_address,
            token_address=test_state.token_address,
        )
        == test_state.token_network_address
    )


def test_listings():
    test_state = factories.make_chain_state(number_of_channels=3)
    assert (
        views.get_token_network_addresses(
            chain_state=test_state.chain_state,
            token_network_registry_address=factories.make_address(),
        )
        == []
    )
    assert (
        views.get_token_network_addresses(
            chain_state=test_state.chain_state,
            token_network_registry_address=test_state.token_network_registry_address,
        )
        == [test_state.token_network_address]
    )
    assert (
        views.get_token_identifiers(
            chain_state=test_state.chain_state,
            token_network_registry_address=factories.make_address(),
        )
        == []
    )
    assert (
        views.get_token_identifiers(
            chain_state=test_state.chain_state,
            token_network_registry_address=test_state.token_network_registry_address,
        )
        == [test_state.token_address]
    )
    assert views.get_token_network_registry_address(chain_state=test_state.chain_state) == [
        test_state.token_network_registry_address
    ]


def test_get_networks(chain_state, token_network_address):
    orig_chain_state = deepcopy(chain_state)
    token_address = factories.make_address()
    token_network_registry_empty = TokenNetworkRegistryState(
        address=factories.make_address(), token_network_list=[]
    )
    chain_state.identifiers_to_tokennetworkregistries[
        token_network_registry_empty.address
    ] = token_network_registry_empty
    assert (
        get_networks(
            chain_state=chain_state,
            token_network_registry_address=token_network_registry_empty.address,
            token_address=token_address,
        )
        == (token_network_registry_empty, None)
    )

    chain_state = orig_chain_state
    token_network = TokenNetworkState(
        address=token_network_address,
        token_address=token_address,
    )
    token_network_registry = TokenNetworkRegistryState(
        address=factories.make_address(), token_network_list=[token_network]
    )
    assert (
        get_networks(
            chain_state=chain_state,
            token_network_registry_address=token_network_registry.address,
            token_address=token_address,
        )
        == (None, None)
    )
    chain_state.identifiers_to_tokennetworkregistries[
        token_network_registry.address
    ] = token_network_registry
    assert (
        get_networks(
            chain_state=chain_state,
            token_network_registry_address=token_network_registry.address,
            token_address=token_address,
        )
        == (token_network_registry, token_network)
    )
