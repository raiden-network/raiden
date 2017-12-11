# -*- coding: utf-8 -*-
from binascii import hexlify, unhexlify

import ethereum.db
import ethereum.blocks
import ethereum.config
from ethereum import tester
from ethereum.utils import int_to_addr, zpad

from raiden.utils import (
    address_decoder,
    data_decoder,
    quantity_decoder,
)
from raiden.tests.utils.blockchain import DEFAULT_BALANCE
from raiden.constants import (
    NETTINGCHANNEL_SETTLE_TIMEOUT_MIN,
    NETTINGCHANNEL_SETTLE_TIMEOUT_MAX
)
from raiden.blockchain.abi import (
    CONTRACT_MANAGER,
    CONTRACT_CHANNEL_MANAGER,
    CONTRACT_HUMAN_STANDARD_TOKEN,
    CONTRACT_NETTING_CHANNEL,
    CONTRACT_REGISTRY,
)
from raiden.channel import Channel, ChannelEndState
from raiden.utils import privatekey_to_address, get_contract_path
from raiden.transfer.merkle_tree import EMPTY_MERKLE_TREE


class InvalidKey(str):
    # using an invalid key as the proxies default_key to force the user to set
    # `sender`. The reason for this is that too many tests were mixing the
    # wrong key, the alternative was to instantiate a proxy per key, which was
    # adding to much code-bloat, using an invalid key we effectvelly disable
    # the "feature" of the ABIContract to use a default key, making all the
    # calls explicit, this is intentional!
    def __getitem__(self, key):
        # please provide an explicit key while testing with tester
        raise Exception('sender key was not set')


INVALID_KEY = InvalidKey('default_key_was_not_set')


def create_tester_state(deploy_key, private_keys, tester_blockgas_limit):
    tester_state = tester.state()

    # special addresses 1 to 5
    alloc = {
        int_to_addr(i): {'wei': 1}
        for i in range(1, 5)
    }

    for privkey in [deploy_key] + private_keys:
        address = privatekey_to_address(privkey)
        alloc[address] = {
            'balance': DEFAULT_BALANCE,
        }

    for account in tester.accounts:
        alloc[account] = {
            'balance': DEFAULT_BALANCE,
        }

    db = ethereum.db.EphemDB()
    env = ethereum.config.Env(
        db,
        ethereum.config.default_config,
    )
    genesis_overwrite = {
        'nonce': zpad(data_decoder('0x00006d6f7264656e'), 8),
        'difficulty': quantity_decoder('0x20000'),
        'mixhash': zpad(b'\x00', 32),
        'coinbase': address_decoder('0x0000000000000000000000000000000000000000'),
        'timestamp': 0,
        'extra_data': b'',
        'gas_limit': tester_blockgas_limit,
        'start_alloc': alloc,
    }
    genesis_block = ethereum.blocks.genesis(
        env,
        **genesis_overwrite
    )

    # enable DELEGATECALL opcode
    genesis_block.number = genesis_block.config['HOMESTEAD_FORK_BLKNUM'] + 1

    tester_state.db = db
    tester_state.env = env
    tester_state.block = genesis_block
    tester_state.blocks = [genesis_block]

    return tester_state


def approve_and_deposit(tester_token, nettingcontract, deposit, key):
    assert tester_token.approve(
        nettingcontract.address,
        deposit,
        sender=key,
    )

    assert nettingcontract.deposit(
        deposit,
        sender=key,
    )


def deploy_standard_token(deploy_key, tester_state, token_amount):
    standard_token_path = get_contract_path('StandardToken.sol')
    human_token_path = get_contract_path('HumanStandardToken.sol')

    standard_token_address = tester_state.contract(
        None,
        path=standard_token_path,
        language='solidity',
    )
    tester_state.mine(number_of_blocks=1)

    human_token_libraries = {
        'StandardToken': hexlify(standard_token_address),
    }
    # using abi_contract because of the constructor_parameters
    human_token_proxy = tester_state.abi_contract(
        None,
        path=human_token_path,
        language='solidity',
        libraries=human_token_libraries,
        constructor_parameters=[token_amount, 'raiden', 0, 'rd'],
        sender=deploy_key,
    )
    tester_state.mine(number_of_blocks=1)

    human_token_address = human_token_proxy.address
    return human_token_address


def deploy_nettingchannel_library(deploy_key, tester_state):
    netting_library_path = get_contract_path('NettingChannelLibrary.sol')
    netting_channel_library_address = tester_state.contract(
        None,
        path=netting_library_path,
        language='solidity',
        contract_name='NettingChannelLibrary',
        sender=deploy_key,
    )
    tester_state.mine(number_of_blocks=1)
    return netting_channel_library_address


def deploy_channelmanager_library(deploy_key, tester_state, tester_nettingchannel_library_address):
    channelmanager_library_path = get_contract_path('ChannelManagerLibrary.sol')
    manager_address = tester_state.contract(
        None,
        path=channelmanager_library_path,
        language='solidity',
        contract_name='ChannelManagerLibrary',
        libraries={
            'NettingChannelLibrary': hexlify(tester_nettingchannel_library_address),
        },
        sender=deploy_key,
    )
    tester_state.mine(number_of_blocks=1)
    return manager_address


def deploy_registry(deploy_key, tester_state, channel_manager_library_address):
    registry_path = get_contract_path('Registry.sol')
    registry_address = tester_state.contract(
        None,
        path=registry_path,
        language='solidity',
        contract_name='Registry',
        libraries={
            'ChannelManagerLibrary': hexlify(channel_manager_library_address)
        },
        sender=deploy_key,
    )
    tester_state.mine(number_of_blocks=1)
    return registry_address


def create_tokenproxy(tester_state, tester_token_address, log_listener):
    translator = tester.ContractTranslator(
        CONTRACT_MANAGER.get_abi(CONTRACT_HUMAN_STANDARD_TOKEN)
    )
    token_abi = tester.ABIContract(
        tester_state,
        translator,
        tester_token_address,
        log_listener=log_listener,
        default_key=INVALID_KEY,
    )
    return token_abi


def create_registryproxy(tester_state, tester_registry_address, log_listener):
    translator = tester.ContractTranslator(CONTRACT_MANAGER.get_abi(CONTRACT_REGISTRY))
    registry_abi = tester.ABIContract(
        tester_state,
        translator,
        tester_registry_address,
        log_listener=log_listener,
        default_key=INVALID_KEY,
    )
    return registry_abi


def create_channelmanager_proxy(tester_state, tester_channelmanager_address, log_listener):
    translator = tester.ContractTranslator(
        CONTRACT_MANAGER.get_abi(CONTRACT_CHANNEL_MANAGER)
    )
    channel_manager_abi = tester.ABIContract(
        tester_state,
        translator,
        tester_channelmanager_address,
        log_listener=log_listener,
        default_key=INVALID_KEY,
    )
    return channel_manager_abi


def create_nettingchannel_proxy(tester_state, tester_nettingchannel_address, log_listener):
    translator = tester.ContractTranslator(
        CONTRACT_MANAGER.get_abi(CONTRACT_NETTING_CHANNEL)
    )
    netting_channel_abi = tester.ABIContract(
        tester_state,
        translator,
        tester_nettingchannel_address,
        log_listener=log_listener,
        default_key=INVALID_KEY,
    )
    return netting_channel_abi


def channel_from_nettingcontract(
        our_key,
        netting_contract,
        external_state,
        reveal_timeout):
    """ Create a `channel.Channel` for the `netting_contract`.

    Use this to make sure that both implementations (the smart contract and the
    python code) work in tandem.
    """
    our_address = privatekey_to_address(our_key)

    token_address_hex = netting_contract.tokenAddress(sender=our_key)
    settle_timeout = netting_contract.settleTimeout(sender=our_key)

    address_balance = netting_contract.addressAndBalance(sender=our_key)
    address1_hex, balance1, address2_hex, balance2 = address_balance

    token_address = unhexlify(token_address_hex)
    address1 = unhexlify(address1_hex)
    address2 = unhexlify(address2_hex)

    if our_address == address1:
        our_balance = balance1
        partner_address = address2
        partner_balance = balance2
    else:
        our_balance = balance2
        partner_address = address1
        partner_balance = balance1

    our_state = ChannelEndState(
        our_address,
        our_balance,
        None,
        EMPTY_MERKLE_TREE,
    )
    partner_state = ChannelEndState(
        partner_address,
        partner_balance,
        None,
        EMPTY_MERKLE_TREE,
    )

    channel = Channel(
        our_state,
        partner_state,
        external_state,
        token_address,
        reveal_timeout,
        settle_timeout,
    )

    return channel


def new_registry(deploy_key, tester_state, channel_manager_library_address, log_listener):
    registry_address = deploy_registry(
        deploy_key,
        tester_state,
        channel_manager_library_address,
    )

    registry = create_registryproxy(
        tester_state,
        registry_address,
        log_listener,
    )
    return registry


def new_token(deploy_key, tester_state, token_amount, log_listener):
    token_address = deploy_standard_token(
        deploy_key,
        tester_state,
        token_amount,
    )

    token = create_tokenproxy(
        tester_state,
        token_address,
        log_listener,
    )
    return token


def new_channelmanager(
        deploy_key,
        tester_state,
        log_listener,
        tester_registry,
        tester_token_address):

    channel_manager_address = tester_registry.addToken(
        tester_token_address,
        sender=deploy_key,
    )
    tester_state.mine(number_of_blocks=1)

    channelmanager = create_channelmanager_proxy(
        tester_state,
        channel_manager_address,
        log_listener,
    )
    return channelmanager


def new_nettingcontract(
        our_key,
        partner_key,
        tester_state,
        log_listener,
        channelmanager,
        settle_timeout):

    invalid_timeout = (
        settle_timeout < NETTINGCHANNEL_SETTLE_TIMEOUT_MIN or
        settle_timeout > NETTINGCHANNEL_SETTLE_TIMEOUT_MAX
    )
    if invalid_timeout:
        raise ValueError('settle_timeout must be in range [{}, {}]'.format(
            NETTINGCHANNEL_SETTLE_TIMEOUT_MIN, NETTINGCHANNEL_SETTLE_TIMEOUT_MAX
        ))

    netting_channel_address0_hex = channelmanager.newChannel(
        privatekey_to_address(partner_key),
        settle_timeout,
        sender=our_key,
    )
    tester_state.mine(number_of_blocks=1)

    nettingchannel = create_nettingchannel_proxy(
        tester_state,
        netting_channel_address0_hex,
        log_listener,
    )

    return nettingchannel
