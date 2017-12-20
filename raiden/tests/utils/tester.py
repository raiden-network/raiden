# -*- coding: utf-8 -*-
from binascii import hexlify

from ethereum.tools import tester, _solidity
from ethereum.utils import normalize_address

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


def create_tester_chain(deploy_key, private_keys, tester_blockgas_limit):
    alloc = {}

    for privkey in [deploy_key] + private_keys:
        address = privatekey_to_address(privkey)
        alloc[address] = {
            'balance': DEFAULT_BALANCE,
        }

    for account in tester.accounts:
        alloc[account] = {
            'balance': DEFAULT_BALANCE,
        }

    tester.k0 = deploy_key
    tester.a0 = privatekey_to_address(deploy_key)

    return tester.Chain(alloc)


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


def deploy_standard_token(deploy_key, tester_chain, token_amount):
    standard_token_path = get_contract_path('StandardToken.sol')
    human_token_path = get_contract_path('HumanStandardToken.sol')

    standard_token_compiled = _solidity.compile_contract(
        standard_token_path,
        "StandardToken"
    )
    standard_token_address = tester_chain.contract(
        standard_token_compiled['bin'],
        language='evm'
    )
    tester_chain.mine(number_of_blocks=1)

    contract_libraries = {
        'StandardToken': hexlify(standard_token_address),
    }

    human_token_compiled = _solidity.compile_contract(
        human_token_path,
        'HumanStandardToken',
        contract_libraries
    )
    ct = tester.ContractTranslator(human_token_compiled['abi'])
    human_token_args = ct.encode_constructor_arguments([token_amount, 'raiden', 0, 'rd'])
    human_token_address = tester_chain.contract(
        human_token_compiled['bin'] + human_token_args,
        language='evm',
        sender=deploy_key
    )
    tester_chain.mine(number_of_blocks=1)

    return human_token_address


def deploy_nettingchannel_library(deploy_key, tester_chain):
    netting_library_path = get_contract_path('NettingChannelLibrary.sol')

    netting_library_compiled = _solidity.compile_contract(
        netting_library_path,
        "NettingChannelLibrary"
    )
    netting_channel_library_address = tester_chain.contract(
        netting_library_compiled['bin'],
        language='evm',
        sender=deploy_key
    )
    tester_chain.mine(number_of_blocks=1)

    return netting_channel_library_address


def deploy_channelmanager_library(deploy_key, tester_chain, tester_nettingchannel_library_address):
    channelmanager_library_path = get_contract_path('ChannelManagerLibrary.sol')

    contract_libraries = {
        'NettingChannelLibrary': hexlify(tester_nettingchannel_library_address),
    }

    channelmanager_library_compiled = _solidity.compile_contract(
        channelmanager_library_path,
        'ChannelManagerLibrary',
        contract_libraries
    )
    channelmanager_library_address = tester_chain.contract(
        channelmanager_library_compiled['bin'],
        language='evm'
    )
    tester_chain.mine(number_of_blocks=1)

    return channelmanager_library_address


def deploy_registry(deploy_key, tester_chain, channel_manager_library_address):
    registry_path = get_contract_path('Registry.sol')
    contract_libraries = {
        'ChannelManagerLibrary': hexlify(channel_manager_library_address),
    }

    registry_compiled = _solidity.compile_contract(
        registry_path,
        'Registry',
        contract_libraries
    )
    registry_address = tester_chain.contract(
        registry_compiled['bin'],
        language='evm',
        sender=deploy_key
    )
    tester_chain.mine(number_of_blocks=1)

    return registry_address


def create_tokenproxy(tester_chain, tester_token_address, log_listener):
    translator = tester.ContractTranslator(
        CONTRACT_MANAGER.get_abi(CONTRACT_HUMAN_STANDARD_TOKEN)
    )
    tester_chain.head_state.log_listeners.append(log_listener)
    token_abi = tester.ABIContract(
        tester_chain,
        translator,
        tester_token_address,
    )
    return token_abi


def create_registryproxy(tester_chain, tester_registry_address, log_listener):
    translator = tester.ContractTranslator(CONTRACT_MANAGER.get_abi(CONTRACT_REGISTRY))
    tester_chain.head_state.log_listeners.append(log_listener)
    registry_abi = tester.ABIContract(
        tester_chain,
        translator,
        tester_registry_address,
    )
    return registry_abi


def create_channelmanager_proxy(tester_chain, tester_channelmanager_address, log_listener):
    translator = tester.ContractTranslator(
        CONTRACT_MANAGER.get_abi(CONTRACT_CHANNEL_MANAGER)
    )
    channel_manager_abi = tester.ABIContract(
        tester_chain,
        translator,
        tester_channelmanager_address,
    )
    tester_chain.head_state.log_listeners.append(log_listener)
    return channel_manager_abi


def create_nettingchannel_proxy(tester_chain, tester_nettingchannel_address, log_listener):
    translator = tester.ContractTranslator(
        CONTRACT_MANAGER.get_abi(CONTRACT_NETTING_CHANNEL)
    )
    tester_chain.head_state.log_listeners.append(log_listener)
    netting_channel_abi = tester.ABIContract(
        tester_chain,
        translator,
        tester_nettingchannel_address,
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

    token_address = normalize_address(token_address_hex)
    address1 = normalize_address(address1_hex)
    address2 = normalize_address(address2_hex)

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


def new_registry(deploy_key, tester_chain, channel_manager_library_address, log_listener):
    registry_address = deploy_registry(
        deploy_key,
        tester_chain,
        channel_manager_library_address,
    )
    tester_chain.head_state.log_listeners.append(log_listener)

    registry = create_registryproxy(
        tester_chain,
        registry_address,
        log_listener,
    )
    return registry


def new_token(deploy_key, tester_chain, token_amount, log_listener):
    token_address = deploy_standard_token(
        deploy_key,
        tester_chain,
        token_amount,
    )
    tester_chain.head_state.log_listeners.append(log_listener)

    token = create_tokenproxy(
        tester_chain,
        token_address,
        log_listener,
    )
    return token


def new_channelmanager(
        deploy_key,
        tester_chain,
        log_listener,
        tester_registry,
        tester_token_address):

    channel_manager_address = tester_registry.addToken(
        tester_token_address,
        sender=deploy_key,
    )
    tester_chain.mine(number_of_blocks=1)

    channelmanager = create_channelmanager_proxy(
        tester_chain,
        channel_manager_address,
        log_listener,
    )
    return channelmanager


def new_nettingcontract(
        our_key,
        partner_key,
        tester_chain,
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
    tester_chain.mine(number_of_blocks=1)

    nettingchannel = create_nettingchannel_proxy(
        tester_chain,
        netting_channel_address0_hex,
        log_listener,
    )

    return nettingchannel
