# -*- coding: utf-8 -*-
import pytest
from ethereum.utils import normalize_address

from raiden.utils import privatekey_to_address
from raiden.tests.utils.tester import (
    create_tester_chain,
    approve_and_deposit,
    channel_from_nettingcontract,
    create_registryproxy,
    create_tokenproxy,
    deploy_channelmanager_library,
    deploy_nettingchannel_library,
    deploy_registry,
    deploy_standard_token,
    new_channelmanager,
    new_nettingcontract,
)
from raiden.tests.utils.tester_client import ChannelExternalStateTester


@pytest.fixture
def tester_blockgas_limit():
    """ The tester's block gas limit.

    Set this value to `GAS_LIMIT` if the test needs to consider the gas usage.

    Note:
        `GAS_LIMIT` is defined in `raiden.network.rpc.client.GAS_LIMIT`
    """
    return 10 ** 10


@pytest.fixture
def tester_events():
    return list()


@pytest.fixture
def tester_chain(deploy_key, private_keys, tester_blockgas_limit):
    return create_tester_chain(deploy_key, private_keys, tester_blockgas_limit)


@pytest.fixture
def tester_token_address(private_keys, token_amount, tester_chain, sender_index=0):
    deploy_key = private_keys[sender_index]

    return deploy_standard_token(
        deploy_key,
        tester_chain,
        token_amount,
    )


@pytest.fixture
def tester_nettingchannel_library_address(deploy_key, tester_chain):
    return deploy_nettingchannel_library(
        deploy_key,
        tester_chain,
    )


@pytest.fixture
def tester_channelmanager_library_address(
        deploy_key,
        tester_chain,
        tester_nettingchannel_library_address):
    return deploy_channelmanager_library(
        deploy_key,
        tester_chain,
        tester_nettingchannel_library_address,
    )


@pytest.fixture
def tester_registry_address(tester_chain, deploy_key, tester_channelmanager_library_address):
    return deploy_registry(
        deploy_key,
        tester_chain,
        tester_channelmanager_library_address,
    )


@pytest.fixture
def tester_token_raw(tester_chain, tester_token_address, tester_events):
    return create_tokenproxy(
        tester_chain,
        tester_token_address,
        tester_events.append,
    )


@pytest.fixture
def tester_token(token_amount, private_keys, tester_chain, tester_token_address, tester_events):
    token = create_tokenproxy(
        tester_chain,
        tester_token_address,
        tester_events.append,
    )

    privatekey0 = private_keys[0]
    for transfer_to in private_keys[1:]:
        token.transfer(  # pylint: disable=no-member
            privatekey_to_address(transfer_to),
            token_amount // len(private_keys),
            sender=privatekey0,
        )

    return token


@pytest.fixture
def tester_registry(tester_chain, tester_registry_address, tester_events):
    return create_registryproxy(
        tester_chain,
        tester_registry_address,
        tester_events.append,
    )


@pytest.fixture
def tester_channelmanager(
        private_keys,
        tester_chain,
        tester_events,
        tester_registry,
        tester_token):
    privatekey0 = private_keys[0]
    channel_manager = new_channelmanager(
        privatekey0,
        tester_chain,
        tester_events.append,
        tester_registry,
        tester_token.address,
    )
    return channel_manager


@pytest.fixture
def tester_nettingcontracts(
        deposit,
        both_participants_deposit,
        private_keys,
        settle_timeout,
        tester_chain,
        tester_events,
        tester_channelmanager,
        tester_token):
    raiden_chain = list(zip(private_keys[:-1], private_keys[1:]))

    result = list()
    for pos, (first_key, second_key) in enumerate(raiden_chain, start=1):

        # tester.py log_listener is enabled for the whole tester, meaning that
        # a log_listener will receive all events that it can decode, even if
        # the event is from a different contract, because of that we _must_
        # only install the log_listener for the first ABI, otherwise the logs
        # will be repeated for each ABI
        if pos == 1:
            log_listener = tester_events.append

        nettingcontract = new_nettingcontract(
            first_key,
            second_key,
            tester_chain,
            log_listener,
            tester_channelmanager,
            settle_timeout,
        )
        result.append(
            (first_key, second_key, nettingcontract),
        )

        approve_and_deposit(
            tester_token,
            nettingcontract,
            deposit,
            first_key,
        )

        if both_participants_deposit:
            approve_and_deposit(
                tester_token,
                nettingcontract,
                deposit,
                second_key,
            )

    return result


@pytest.fixture
def tester_channels(tester_chain, tester_nettingcontracts, reveal_timeout):
    result = list()
    for first_key, second_key, nettingcontract in tester_nettingcontracts:
        first_externalstate = ChannelExternalStateTester(
            tester_chain,
            first_key,
            normalize_address(nettingcontract.address),
        )
        first_channel = channel_from_nettingcontract(
            first_key,
            nettingcontract,
            first_externalstate,
            reveal_timeout,
        )

        second_externalstate = ChannelExternalStateTester(
            tester_chain,
            second_key,
            normalize_address(nettingcontract.address),
        )
        second_channel = channel_from_nettingcontract(
            second_key,
            nettingcontract,
            second_externalstate,
            reveal_timeout,
        )

        result.append(
            (first_key, second_key, nettingcontract, first_channel, second_channel)
        )

    return result
