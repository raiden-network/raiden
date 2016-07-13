# -*- coding: utf8 -*-
import pytest

from ethereum._solidity import compile_file
from ethereum import tester
from ethereum.utils import sha3
from ethereum.tester import ABIContract, ContractTranslator, TransactionFailed
from ethereum.slogging import configure

from raiden.blockchain.abi import get_contract_path

# pylint: disable=no-member
configure(':DEBUG')


# TODO: test events
def test_cmc():  # pylint: disable=too-many-locals,too-many-statements
    iterable_mapping_path = get_contract_path('IterableMappingNCC.sol')
    channel_manager_path = get_contract_path('ChannelManagerContract.sol')
    netting_channel_path = get_contract_path('NettingChannelContract.sol')
    decoder_lib_path = get_contract_path('Dcdr.sol')

    settle_timeout = 30

    address1 = sha3('address1')[:20]
    address3 = sha3('address3')[:20]
    inexisting_address = sha3('this_does_not_exist')[:20]
    asset_address_hex = sha3('asset')[:20].encode('hex')

    netting_channel_compiled = compile_file(netting_channel_path)['NettingChannelContract']
    netting_channel_abi = netting_channel_compiled['abi']
    netting_channel_translator = ContractTranslator(netting_channel_abi)

    tester.gas_limit = 9575081L
    state = tester.state()
    state.block.number = 1158001

    iterrable_mapping_proxy = state.abi_contract(
        None,
        path=iterable_mapping_path,
        language='solidity',
    )

    decoder_address = state.contract(
        None,
        path=decoder_lib_path,
        language='solidity',
    )

    channel_manager_libraries = {
        'IterableMappingNCC': iterrable_mapping_proxy.address.encode('hex'),
        'Dcdr': decoder_address.encode('hex'),
    }

    channel_manager_proxy = state.abi_contract(
        None,
        path=channel_manager_path,
        language='solidity',
        libraries=channel_manager_libraries,
        constructor_parameters=['0x' +  asset_address_hex],
    )

    assert channel_manager_proxy.assetToken() == asset_address_hex
    assert len(channel_manager_proxy.getAllChannels()) == 0

    netting_channel_address1 = channel_manager_proxy.newChannel(
        address1,
        settle_timeout,
    )

    # cannot have two channels at the same time
    with pytest.raises(TransactionFailed):
        channel_manager_proxy.newChannel(address1, settle_timeout)

    # should trow if there is no channel for the given address
    with pytest.raises(TransactionFailed):
        channel_manager_proxy.get(inexisting_address)

    assert len(channel_manager_proxy.getAllChannels()) == 2

    netting_contract_proxy1 = ABIContract(
        state,
        netting_channel_translator,
        netting_channel_address1,
    )

    assert netting_contract_proxy1.settleTimeout() == settle_timeout

    netting_channel_address2 = channel_manager_proxy.newChannel(
        address3,
        settle_timeout,
    )

    assert channel_manager_proxy.get(address1) == netting_channel_address1
    assert channel_manager_proxy.get(address3) == netting_channel_address2

    msg_sender_channels = channel_manager_proxy.nettingContractsByAddress(tester.DEFAULT_ACCOUNT)
    address1_channels = channel_manager_proxy.nettingContractsByAddress(address1)
    inexisting_channels = channel_manager_proxy.nettingContractsByAddress(inexisting_address)

    assert len(msg_sender_channels) == 2
    assert len(address1_channels) == 1
    assert len(inexisting_channels) == 0

    assert len(channel_manager_proxy.getAllChannels()) == 4

    # uncomment private in function to run test
    # assert channel_manager_proxy.numberOfItems(netting_channel_creator1) == 2
    # assert channel_manager_proxy.numberOfItems(sha3('address1')[:20]) == 1
    # assert channel_manager_proxy.numberOfItems(sha3('iDontExist')[:20]) == 0
    # vs = sorted((sha3('address1')[:20], sha3('address2')[:20]))
    # k0 = channel_manager_proxy.key(sha3('address1')[:20], sha3('address2')[:20])
    # assert k0 == sha3(vs[0] + vs[1])
    # k1 = channel_manager_proxy.key(sha3('address2')[:20], sha3('address1')[:20])
    # assert k1 == sha3(vs[0] + vs[1])
    # with pytest.raises(TransactionFailed):
    #    channel_manager_proxy.key(sha3('address1')[:20], sha3('address1')[:20])
