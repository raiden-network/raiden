# -*- coding: utf8 -*-
import pytest

from ethereum import utils
from ethereum import tester
from ethereum.utils import sha3, privtoaddr
from ethereum.tester import TransactionFailed
from ethereum.slogging import configure

from raiden.network.rpc.client import get_contract_path


def test_registry():
    library_path = get_contract_path('IterableMappingCMC.sol')
    ncc_path = get_contract_path('IterableMappingNCC.sol')
    decoder_path = get_contract_path('Decoder.sol')
    registry_path = get_contract_path('Registry.sol')

    s = tester.state()
    assert s.block.number < 1150000
    s.block.number = 1158001
    assert s.block.number > 1150000
    lib_c = s.abi_contract(None, path=library_path, language="solidity")
    s.mine()
    lib_ncc = s.abi_contract(None, path=ncc_path, language="solidity")
    s.mine()
    lib_dec = s.abi_contract(None, path=decoder_path, language="solidity")
    s.mine()
    c = s.abi_contract(None, path=registry_path, language="solidity", libraries={'IterableMappingCMC': lib_c.address.encode('hex'), 'IterableMappingNCC': lib_ncc.address.encode('hex'), 'Decoder': lib_dec.address.encode('hex')})

    contract_address = c.addAsset(sha3('asset')[:20])
    c.addAsset(sha3('address')[:20])
    # if address already exists, throw
    with pytest.raises(TransactionFailed):
        c.addAsset(sha3('asset')[:20])

    cmc = c.channelManagerByAsset(sha3('asset')[:20])
    assert cmc == contract_address
    # if address does not exist, throw
    with pytest.raises(TransactionFailed):
        c.channelManagerByAsset(sha3('mainz')[:20])

    adrs = c.assetAddresses()
    assert len(adrs) == 2
    assert adrs[0] == sha3('asset')[:20].encode('hex')
    assert adrs[1] == sha3('address')[:20].encode('hex')
