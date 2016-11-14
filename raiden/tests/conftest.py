# -*- coding: utf-8 -*-
import pytest
import gevent
import gevent.monkey
from ethereum import slogging
from ethereum.keys import PBKDF2_CONSTANTS
from ethereum import processblock
from ethereum import tester

from raiden.network.rpc.client import GAS_LIMIT

from raiden.tests.fixtures import (
    token_abi,
    registry_abi,
    channel_manager_abi,
    netting_channel_abi,

    assets_addresses,
    cached_genesis,
    blockchain_services,
    blockchain_backend,

    raiden_chain,
    raiden_network,

    tester_blockgas_limit,
    tester_events,
    tester_state,
    tester_token_address,
    tester_nettingchannel_library_address,
    tester_channelmanager_library_address,
    tester_registry_address,
    tester_token_raw,
    tester_token,
    tester_registry,
    tester_channelmanager,
    tester_nettingcontracts,
    tester_channels,

    settle_timeout,
    reveal_timeout,
    events_poll_timeout,
    deposit,
    number_of_assets,
    number_of_nodes,
    channels_per_node,
    poll_timeout,
    transport_class,
    privatekey_seed,
    asset_amount,
    private_keys,
    deploy_key,
    blockchain_type,
    blockchain_number_of_nodes,
    blockchain_key_seed,
    blockchain_private_keys,
    blockchain_p2p_base_port,
)

__all__ = (
    'token_abi',
    'registry_abi',
    'channel_manager_abi',
    'netting_channel_abi',

    'assets_addresses',
    'cached_genesis',
    'blockchain_services',
    'blockchain_backend',

    'raiden_chain',
    'raiden_network',

    'tester_blockgas_limit',
    'tester_events',
    'tester_state',
    'tester_token_address',
    'tester_nettingchannel_library_address',
    'tester_channelmanager_library_address',
    'tester_registry_address',
    'tester_token_raw',
    'tester_token',
    'tester_registry',
    'tester_channelmanager',
    'tester_nettingcontracts',
    'tester_channels',

    'settle_timeout',
    'reveal_timeout',
    'events_poll_timeout',
    'deposit',
    'number_of_assets',
    'number_of_nodes',
    'channels_per_node',
    'poll_timeout',
    'transport_class',
    'privatekey_seed',
    'asset_amount',
    'private_keys',
    'deploy_key',
    'blockchain_type',
    'blockchain_number_of_nodes',
    'blockchain_key_seed',
    'blockchain_private_keys',
    'blockchain_p2p_base_port',

    'pytest_addoption',
    'logging_level',
    'enable_greenlet_debugger',
)

gevent.monkey.patch_socket()
gevent.get_hub().SYSTEM_ERROR = BaseException
PBKDF2_CONSTANTS['c'] = 100


def pytest_addoption(parser):
    parser.addoption(
        '--blockchain-type',
        choices=['geth', 'tester', 'mock'],
        default='geth',
    )

    parser.addoption(
        '--blockchain-cache',
        action='store_true',
        default=False,
    )

    parser.addoption(
        '--log-config',
        default=None,
    )


@pytest.fixture(autouse=True)
def logging_level(request):
    """ Configure the logging level.

    For integration tests this also sets the geth verbosity.
    """
    if request.config.option.log_config is not None:
        slogging.configure(request.config.option.log_config)

    elif request.config.option.verbose > 5:
        slogging.configure(':TRACE')

    elif request.config.option.verbose > 3:
        slogging.configure(':DEBUG')

    elif request.config.option.verbose > 1:
        slogging.configure(':INFO')

    else:
        slogging.configure(':WARNING')


@pytest.fixture(scope='session', autouse=True)
def enable_greenlet_debugger(request):
    if request.config.option.usepdb:
        from pyethapp.utils import enable_greenlet_debugger
        enable_greenlet_debugger()


@pytest.fixture(scope='session', autouse=True)
def monkey_patch_tester():
    original_apply_transaction = processblock.apply_transaction

    def apply_transaction(block, transaction):
        start_gas = block.gas_used
        result = original_apply_transaction(block, transaction)
        end_gas = block.gas_used

        assert end_gas - start_gas <= GAS_LIMIT

        return result

    tester.processblock.apply_transaction = apply_transaction
