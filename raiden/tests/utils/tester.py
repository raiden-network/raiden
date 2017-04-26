# -*- coding: utf-8 -*-
from ethereum import tester
from ethereum.utils import decode_hex

from raiden.blockchain.abi import (
    CHANNEL_MANAGER_ABI,
    NETTING_CHANNEL_ABI,
    HUMAN_TOKEN_ABI,
    REGISTRY_ABI,
)
from raiden.channel import Channel, ChannelEndState
from raiden.utils import privatekey_to_address


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


def create_tokenproxy(tester_state, tester_token_address, log_listener):
    translator = tester.ContractTranslator(HUMAN_TOKEN_ABI)
    token_abi = tester.ABIContract(
        tester_state,
        translator,
        tester_token_address,
        log_listener=log_listener,
        default_key=INVALID_KEY,
    )
    return token_abi


def create_registryproxy(tester_state, tester_registry_address, log_listener):
    translator = tester.ContractTranslator(REGISTRY_ABI)
    registry_abi = tester.ABIContract(
        tester_state,
        translator,
        tester_registry_address,
        log_listener=log_listener,
        default_key=INVALID_KEY,
    )
    return registry_abi


def create_channelmanager_proxy(tester_state, tester_channelmanager_address, log_listener):
    translator = tester.ContractTranslator(CHANNEL_MANAGER_ABI)
    channel_manager_abi = tester.ABIContract(
        tester_state,
        translator,
        tester_channelmanager_address,
        log_listener=log_listener,
        default_key=INVALID_KEY,
    )
    return channel_manager_abi


def create_nettingchannel_proxy(tester_state, tester_nettingchannel_address, log_listener):
    translator = tester.ContractTranslator(NETTING_CHANNEL_ABI)
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
        reveal_timeout,
        block_number):
    """ Create a `channel.Channel` for the `netting_contract`.

    Use this to make sure that both implementations (the smart contract and the
    python code) work in tandem.
    """
    our_address = privatekey_to_address(our_key)

    token_address_hex = netting_contract.tokenAddress(sender=our_key)
    settle_timeout = netting_contract.settleTimeout(sender=our_key)

    address_balance = netting_contract.addressAndBalance(sender=our_key)
    address1_hex, balance1, address2_hex, balance2 = address_balance

    token_address = decode_hex(token_address_hex)
    address1 = decode_hex(address1_hex)
    address2 = decode_hex(address2_hex)

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
        external_state.opened_block,
    )
    partner_state = ChannelEndState(
        partner_address,
        partner_balance,
        external_state.opened_block,
    )

    channel = Channel(
        our_state,
        partner_state,
        external_state,
        token_address,
        reveal_timeout,
        settle_timeout,
        block_number,
    )

    return channel


def new_channelmanager(our_key, tester_state, log_listener, tester_registry, tester_token):
    channel_manager_address = tester_registry.addToken(
        tester_token.address,
        sender=our_key,
    )
    tester_state.mine(number_of_blocks=1)

    channelmanager = create_channelmanager_proxy(
        tester_state,
        channel_manager_address,
        log_listener,
    )
    return channelmanager


def new_nettingcontract(our_key, partner_key, tester_state, log_listener,
                        channelmanager, settle_timeout):

    netting_channel_address0_hex = channelmanager.newChannel(
        privatekey_to_address(partner_key),
        settle_timeout,
        sender=our_key,
    )
    tester_state.mine(number_of_blocks=1)

    nettingchannel_translator = tester.ContractTranslator(NETTING_CHANNEL_ABI)

    nettingchannel = tester.ABIContract(
        tester_state,
        nettingchannel_translator,
        netting_channel_address0_hex,
        log_listener=log_listener,
        default_key=INVALID_KEY,
    )

    return nettingchannel
