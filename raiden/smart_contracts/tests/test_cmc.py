# -*- coding: utf8 -*-
import pytest
from ethereum import tester
from ethereum.utils import sha3
from ethereum.tester import TransactionFailed

library_path = "raiden/smart_contracts/channelManagerContract.slb"
cmc_path = "raiden/smart_contracts/channelManagerContract.sol"


def test_cmc():
    s = tester.state()
    assert s.block.number < 1150000
    s.block.number = 1158001
    assert s.block.number > 1150000
    lib_c = s.abi_contract(None, path=library_path, language="solidity")
    c = s.abi_contract(None, path=cmc_path, language="solidity", libraries={'IterableMappingNcc': lib_c.address.encode('hex')})

    # test key()
    vs = sorted((sha3('address1')[:20], sha3('address2')[:20]))
    k0 = c.key(sha3('address1')[:20], sha3('address2')[:20])
    assert k0 == sha3(vs[0] + vs[1])
    k1 = c.key(sha3('address2')[:20], sha3('address1')[:20])
    assert k1 == sha3(vs[0] + vs[1])
    with pytest.raises(TransactionFailed):
        c.key(sha3('address1')[:20], sha3('address1')[:20])

    # test newChannel()
    assert c.assetAddress() == sha3('asset')[:20].encode('hex')
    nc1 = c.newChannel(sha3('address1')[:20])
    nc2 = c.newChannel(sha3('address3')[:20])
    with pytest.raises(TransactionFailed):
        c.newChannel(sha3('address1')[:20])
    with pytest.raises(TransactionFailed):
        c.newChannel(sha3('address3')[:20])

    # TODO test event

    # test get()
    chn1 = c.get(nc1[1], sha3('address1')[:20])
    assert chn1 == nc1[0]
    chn2 = c.get(nc2[1], sha3('address3')[:20])
    assert chn2 == nc2[0]
    with pytest.raises(TransactionFailed):  # should throw if key doesn't exist
        c.get(nc1[1], sha3('iDontExist')[:20])

    # test nettingContractsByAddress()
    msg_sender_channels = c.nettingContractsByAddress(nc1[1])
    assert len(msg_sender_channels) == 2
    address1_channels = c.nettingContractsByAddress(sha3('address1')[:20])
    assert len(address1_channels) == 1
    address1_channels = c.nettingContractsByAddress(sha3('iDontExist')[:20])
    assert len(address1_channels) == 0
