""" Utilities to set-up a Raiden network. """
from collections import namedtuple
from copy import deepcopy
from itertools import product

import gevent
import structlog
from eth_utils import to_checksum_address

from raiden import waiting
from raiden.app import App
from raiden.constants import RoutingMode
from raiden.network.blockchain_service import BlockChainService
from raiden.network.rpc.client import JSONRPCClient
from raiden.network.transport import MatrixTransport
from raiden.raiden_event_handler import RaidenEventHandler
from raiden.settings import DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS, DEFAULT_RETRY_TIMEOUT
from raiden.tests.utils.app import database_from_privatekey
from raiden.tests.utils.factories import UNIT_CHAIN_ID
from raiden.tests.utils.protocol import HoldRaidenEventHandler, WaitForMessage
from raiden.transfer.identifiers import CanonicalIdentifier
from raiden.transfer.mediated_transfer.mediation_fee import FeeScheduleState
from raiden.transfer.views import state_from_raiden
from raiden.utils import BlockNumber, merge_dict
from raiden.utils.typing import (
    Address,
    BlockTimeout,
    ChannelID,
    Iterable,
    List,
    Optional,
    PaymentNetworkAddress,
    TokenAddress,
    TokenAmount,
    TokenNetworkAddress,
    Tuple,
)
from raiden.waiting import wait_for_payment_network

AppChannels = Iterable[Tuple[App, App]]

log = structlog.get_logger(__name__)

CHAIN = object()  # Flag used by create a network does make a loop with the channels
BlockchainServices = namedtuple(
    "BlockchainServices",
    (
        "deploy_registry",
        "secret_registry",
        "service_registry",
        "deploy_service",
        "blockchain_services",
    ),
)


def check_channel(
    app1: App,
    app2: App,
    token_network_address: TokenNetworkAddress,
    channel_identifier: ChannelID,
    settle_timeout: BlockTimeout,
    deposit_amount: TokenAmount,
) -> None:
    canonical_identifier = CanonicalIdentifier(
        chain_identifier=state_from_raiden(app1.raiden).chain_id,
        token_network_address=token_network_address,
        channel_identifier=channel_identifier,
    )
    netcontract1 = app1.raiden.chain.payment_channel(canonical_identifier=canonical_identifier)
    netcontract2 = app2.raiden.chain.payment_channel(canonical_identifier=canonical_identifier)

    # Check a valid settle timeout was used, the netting contract has an
    # enforced minimum and maximum
    assert settle_timeout == netcontract1.settle_timeout()
    assert settle_timeout == netcontract2.settle_timeout()

    if deposit_amount > 0:
        assert netcontract1.can_transfer("latest")
        assert netcontract2.can_transfer("latest")

    app1_details = netcontract1.detail("latest")
    app2_details = netcontract2.detail("latest")

    assert (
        app1_details.participants_data.our_details.address
        == app2_details.participants_data.partner_details.address
    )
    assert (
        app1_details.participants_data.partner_details.address
        == app2_details.participants_data.our_details.address
    )

    assert (
        app1_details.participants_data.our_details.deposit
        == app2_details.participants_data.partner_details.deposit
    )
    assert (
        app1_details.participants_data.partner_details.deposit
        == app2_details.participants_data.our_details.deposit
    )
    assert app1_details.chain_id == app2_details.chain_id

    assert app1_details.participants_data.our_details.deposit == deposit_amount
    assert app1_details.participants_data.partner_details.deposit == deposit_amount
    assert app2_details.participants_data.our_details.deposit == deposit_amount
    assert app2_details.participants_data.partner_details.deposit == deposit_amount
    assert app2_details.chain_id == UNIT_CHAIN_ID


def payment_channel_open_and_deposit(
    app0: App,
    app1: App,
    token_address: TokenAddress,
    deposit: TokenAmount,
    settle_timeout: BlockTimeout,
) -> None:
    """ Open a new channel with app0 and app1 as participants """
    assert token_address

    token_network_address = app0.raiden.default_registry.get_token_network(token_address)
    assert token_network_address, "request a channel for an unregistered token"
    token_network_proxy = app0.raiden.chain.token_network(token_network_address)

    channel_identifier = token_network_proxy.new_netting_channel(
        partner=app1.raiden.address, settle_timeout=settle_timeout, given_block_identifier="latest"
    )
    assert channel_identifier
    canonical_identifier = CanonicalIdentifier(
        chain_identifier=state_from_raiden(app0.raiden).chain_id,
        token_network_address=token_network_proxy.address,
        channel_identifier=channel_identifier,
    )

    for app in [app0, app1]:
        # Use each app's own chain because of the private key / local signing
        token = app.raiden.chain.token(token_address)
        payment_channel_proxy = app.raiden.chain.payment_channel(
            canonical_identifier=canonical_identifier
        )

        # This check can succeed and the deposit still fail, if channels are
        # openned in parallel
        previous_balance = token.balance_of(app.raiden.address)
        assert previous_balance >= deposit

        # the payment channel proxy will call approve
        # token.approve(token_network_proxy.address, deposit)
        payment_channel_proxy.set_total_deposit(total_deposit=deposit, block_identifier="latest")

        # Balance must decrease by at least but not exactly `deposit` amount,
        # because channels can be openned in parallel
        new_balance = token.balance_of(app.raiden.address)
        assert new_balance <= previous_balance - deposit

    check_channel(
        app0, app1, token_network_proxy.address, channel_identifier, settle_timeout, deposit
    )


def create_all_channels_for_network(
    app_channels: AppChannels,
    token_addresses: List[TokenAddress],
    channel_individual_deposit: TokenAmount,
    channel_settle_timeout: BlockTimeout,
) -> None:
    greenlets = set()
    for token_address in token_addresses:
        for app_pair in app_channels:
            greenlets.add(
                gevent.spawn(
                    payment_channel_open_and_deposit,
                    app_pair[0],
                    app_pair[1],
                    token_address,
                    channel_individual_deposit,
                    channel_settle_timeout,
                )
            )
    gevent.joinall(greenlets, raise_error=True)

    channels = [
        {
            "app0": to_checksum_address(app0.raiden.address),
            "app1": to_checksum_address(app1.raiden.address),
            "deposit": channel_individual_deposit,
            "token_address": to_checksum_address(token_address),
        }
        for (app0, app1), token_address in product(app_channels, token_addresses)
    ]
    log.info("Test channels", channels=channels)


def network_with_minimum_channels(apps: List[App], channels_per_node: int) -> AppChannels:
    """ Return the channels that should be created so that each app has at
    least `channels_per_node` with the other apps.

    Yields a two-tuple (app1, app2) that must be connected to respect
    `channels_per_node`. Any preexisting channels will be ignored, so the nodes
    might end up with more channels open than `channels_per_node`.
    """
    # pylint: disable=too-many-locals
    if channels_per_node > len(apps):
        raise ValueError("Can't create more channels than nodes")

    if len(apps) == 1:
        raise ValueError("Can't create channels with only one node")

    # If we use random nodes we can hit some edge cases, like the
    # following:
    #
    #  node | #channels
    #   A   |    0
    #   B   |    1  D-B
    #   C   |    1  D-C
    #   D   |    2  D-C D-B
    #
    # B and C have one channel each, and they do not a channel
    # between them, if in this iteration either app is the current
    # one and random choose the other to connect, A will be left
    # with no channels. In this scenario we need to force the use
    # of the node with the least number of channels.

    unconnected_apps = dict()
    channel_count = dict()

    # assume that the apps don't have any connection among them
    for curr_app in apps:
        all_apps = list(apps)
        all_apps.remove(curr_app)
        unconnected_apps[curr_app.raiden.address] = all_apps
        channel_count[curr_app.raiden.address] = 0

    # Create `channels_per_node` channels for each token in each app
    # for token_address, curr_app in product(tokens_list, sorted(apps, key=sort_by_address)):

    # sorting the apps and use the next n apps to make a channel to avoid edge
    # cases
    for curr_app in sorted(apps, key=lambda app: app.raiden.address):
        available_apps = unconnected_apps[curr_app.raiden.address]

        while channel_count[curr_app.raiden.address] < channels_per_node:
            least_connect = sorted(
                available_apps, key=lambda app: channel_count[app.raiden.address]
            )[0]

            channel_count[curr_app.raiden.address] += 1
            available_apps.remove(least_connect)

            channel_count[least_connect.raiden.address] += 1
            unconnected_apps[least_connect.raiden.address].remove(curr_app)

            yield curr_app, least_connect


def create_network_channels(raiden_apps: List[App], channels_per_node: int) -> AppChannels:
    app_channels: AppChannels

    num_nodes = len(raiden_apps)

    if channels_per_node is not CHAIN and channels_per_node > num_nodes:
        raise ValueError("Can't create more channels than nodes")

    if channels_per_node == 0:
        app_channels = []
    elif channels_per_node == CHAIN:
        app_channels = list(zip(raiden_apps[:-1], raiden_apps[1:]))
    else:
        app_channels = list(network_with_minimum_channels(raiden_apps, channels_per_node))

    return app_channels


def create_sequential_channels(raiden_apps: List[App], channels_per_node: int) -> AppChannels:
    """ Create a fully connected network with `num_nodes`, the nodes are
    connect sequentially.

    Returns:
        A list of apps of size `num_nodes`, with the property that every
        sequential pair in the list has an open channel with `deposit` for each
        participant.
    """
    app_channels: AppChannels

    num_nodes = len(raiden_apps)

    if num_nodes < 2:
        raise ValueError("cannot create a network with less than two nodes")

    if channels_per_node not in (0, 1, 2, CHAIN):
        raise ValueError("can only create networks with 0, 1, 2 or CHAIN channels")

    if channels_per_node == 0:
        app_channels = list()

    if channels_per_node == 1:
        assert len(raiden_apps) % 2 == 0, "needs an even number of nodes"
        every_two = iter(raiden_apps)
        app_channels = list(zip(every_two, every_two))

    if channels_per_node == 2:
        app_channels = list(zip(raiden_apps, raiden_apps[1:] + [raiden_apps[0]]))

    if channels_per_node == CHAIN:
        app_channels = list(zip(raiden_apps[:-1], raiden_apps[1:]))

    return app_channels


def create_apps(
    chain_id,
    contracts_path,
    blockchain_services,
    token_network_registry_address,
    one_to_n_address: Optional[Address],
    secret_registry_address,
    service_registry_address,
    user_deposit_address,
    monitoring_service_contract_address,
    reveal_timeout,
    settle_timeout,
    database_basedir,
    retry_interval,
    retries_before_backoff,
    environment_type,
    unrecoverable_error_should_crash,
    local_matrix_url=None,
    private_rooms=None,
    global_rooms=None,
):
    """ Create the apps."""
    # pylint: disable=too-many-locals
    services = blockchain_services

    apps = []
    for idx, blockchain in enumerate(services):
        database_path = database_from_privatekey(base_dir=database_basedir, app_number=idx)

        config = {
            "chain_id": chain_id,
            "environment_type": environment_type,
            "unrecoverable_error_should_crash": unrecoverable_error_should_crash,
            "reveal_timeout": reveal_timeout,
            "settle_timeout": settle_timeout,
            "contracts_path": contracts_path,
            "database_path": database_path,
            "blockchain": {"confirmation_blocks": DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS},
            "transport": {},
            "rpc": True,
            "console": False,
            "default_fee_schedule": FeeScheduleState(),
        }

        use_matrix = local_matrix_url is not None
        if use_matrix:
            merge_dict(
                config,
                {
                    "transport_type": "matrix",
                    "transport": {
                        "matrix": {
                            "global_rooms": global_rooms,
                            "retries_before_backoff": retries_before_backoff,
                            "retry_interval": retry_interval,
                            "server": local_matrix_url,
                            "server_name": local_matrix_url.netloc,
                            "available_servers": [],
                            "private_rooms": private_rooms,
                        }
                    },
                },
            )

        config_copy = deepcopy(App.DEFAULT_CONFIG)
        config_copy.update(config)

        registry = blockchain.token_network_registry(token_network_registry_address)
        secret_registry = blockchain.secret_registry(secret_registry_address)

        service_registry = None
        if service_registry_address:
            service_registry = blockchain.service_registry(service_registry_address)

        user_deposit = None
        if user_deposit_address:
            user_deposit = blockchain.user_deposit(user_deposit_address)

        transport = MatrixTransport(config["transport"]["matrix"])

        raiden_event_handler = RaidenEventHandler()
        hold_handler = HoldRaidenEventHandler(raiden_event_handler)
        message_handler = WaitForMessage()

        app = App(
            config=config_copy,
            chain=blockchain,
            query_start_block=BlockNumber(0),
            default_registry=registry,
            default_one_to_n_address=one_to_n_address,
            default_secret_registry=secret_registry,
            default_service_registry=service_registry,
            default_msc_address=monitoring_service_contract_address,
            transport=transport,
            raiden_event_handler=hold_handler,
            message_handler=message_handler,
            user_deposit=user_deposit,
            routing_mode=RoutingMode.PRIVATE,
        )
        apps.append(app)

    return apps


def parallel_start_apps(raiden_apps: List[App]) -> None:
    """Start all the raiden apps in parallel."""
    start_tasks = set()

    for app in raiden_apps:
        greenlet = gevent.spawn(app.raiden.start)
        greenlet.name = f"Fixture:raiden_network node:{to_checksum_address(app.raiden.address)}"
        start_tasks.add(greenlet)

    gevent.joinall(start_tasks, raise_error=True)

    addresses_in_order = {
        pos: to_checksum_address(app.raiden.address) for pos, app in enumerate(raiden_apps)
    }
    log.info("Raiden Apps started", addresses_in_order=addresses_in_order)


def jsonrpc_services(
    deploy_service,
    private_keys,
    secret_registry_address,
    service_registry_address,
    token_network_registry_address,
    web3,
    contract_manager,
):
    secret_registry = deploy_service.secret_registry(secret_registry_address)
    service_registry = None
    if service_registry_address:
        service_registry = deploy_service.service_registry(service_registry_address)
    deploy_registry = deploy_service.token_network_registry(token_network_registry_address)

    blockchain_services = list()
    for privkey in private_keys:
        rpc_client = JSONRPCClient(web3, privkey)
        blockchain = BlockChainService(
            jsonrpc_client=rpc_client, contract_manager=contract_manager
        )
        blockchain_services.append(blockchain)

    return BlockchainServices(
        deploy_registry=deploy_registry,
        secret_registry=secret_registry,
        service_registry=service_registry,
        deploy_service=deploy_service,
        blockchain_services=blockchain_services,
    )


def wait_for_alarm_start(
    raiden_apps: List[App], retry_timeout: float = DEFAULT_RETRY_TIMEOUT
) -> None:
    """Wait until all Alarm tasks start & set up the last_block"""
    apps = list(raiden_apps)

    while apps:
        app = apps[-1]

        if app.raiden.alarm.known_block_number is None:
            gevent.sleep(retry_timeout)
        else:
            apps.pop()


def wait_for_usable_channel(
    app0: App,
    app1: App,
    registry_address: PaymentNetworkAddress,
    token_address: TokenAddress,
    our_deposit: TokenAmount,
    partner_deposit: TokenAmount,
    retry_timeout: float = DEFAULT_RETRY_TIMEOUT,
) -> None:
    """ Wait until the channel from app0 to app1 is usable.

    The channel and the deposits are registered, and the partner network state
    is reachable.
    """
    waiting.wait_for_newchannel(
        app0.raiden, registry_address, token_address, app1.raiden.address, retry_timeout
    )

    waiting.wait_for_participant_deposit(
        app0.raiden,
        registry_address,
        token_address,
        app1.raiden.address,
        app0.raiden.address,
        our_deposit,
        retry_timeout,
    )

    waiting.wait_for_participant_deposit(
        app0.raiden,
        registry_address,
        token_address,
        app1.raiden.address,
        app1.raiden.address,
        partner_deposit,
        retry_timeout,
    )

    waiting.wait_for_healthy(app0.raiden, app1.raiden.address, retry_timeout)


def wait_for_token_networks(
    raiden_apps: List[App],
    token_network_registry_address: PaymentNetworkAddress,
    token_addresses: List[TokenAddress],
    retry_timeout: float = DEFAULT_RETRY_TIMEOUT,
) -> None:
    for token_address in token_addresses:
        for app in raiden_apps:
            wait_for_payment_network(
                app.raiden, token_network_registry_address, token_address, retry_timeout
            )


def wait_for_channels(
    app_channels: AppChannels,
    registry_address: PaymentNetworkAddress,
    token_addresses: List[TokenAddress],
    deposit: TokenAmount,
    retry_timeout: float = DEFAULT_RETRY_TIMEOUT,
) -> None:
    """ Wait until all channels are usable from both directions. """
    for app0, app1 in app_channels:
        for token_address in token_addresses:
            wait_for_usable_channel(
                app0, app1, registry_address, token_address, deposit, deposit, retry_timeout
            )
            wait_for_usable_channel(
                app1, app0, registry_address, token_address, deposit, deposit, retry_timeout
            )
