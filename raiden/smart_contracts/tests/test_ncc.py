# -*- coding: utf8 -*-
import pytest

from ethereum import utils
from ethereum import tester
from ethereum.utils import sha3, privtoaddr
from ethereum.tester import TransactionFailed

from raiden.network.rpc.client import get_contract_path

from ethereum.slogging import configure

configure("eth.vm:trace, :debug", log_json=True)

library_path = get_contract_path('Decoder.sol')
ncc_path = get_contract_path('NettingChannelContract.sol.old')



def test_ncc():
    s = tester.state()
    assert s.block.number < 1150000
    s.block.number = 1158001
    assert s.block.number > 1150000
    lib_c = s.abi_contract(None, path=library_path, language="solidity")
    s.mine()
    c = s.abi_contract(None, path=ncc_path, language="solidity", libraries={'Decoder': lib_c.address.encode('hex')}, constructor_parameters=[sha3('assetAddress')[:20], sha3('address1')[:20], sha3('address2')[:20], 30])

    # test global variables
    assert c.lockedTime() == 30
    assert c.assetAddress() == sha3('assetAddress')[:20].encode('hex')
    assert c.opened() == 0
    assert c.closed() == 0
    assert c.settled() == 0

    # test participants variables changed when constructing
    assert c.participants(0)[0] == sha3('address1')[:20].encode('hex')
    assert c.participants(1)[0] == sha3('address2')[:20].encode('hex')


    # test atIndex()
    # private must be removed from the function in order to work
    # assert c.atIndex(sha3('address1')[:20]) == 0
    # assert c.atIndex(sha3('address2')[:20]) == 1

    # test deposit(uint)
    # c.deposit(30)
    # TODO find a way to add HumanToken to this test

    # test open()
    # private must be removed from the function in order to work
    # assert c.opened() == 0  # channel is not yet opened
    # c.open()
    # assert c.opened() > 0
    # assert c.opened() <= s.block.number

    # test partner(address)
    # private must be removed from the function in order to work
    # assert c.partner(sha3('address1')[:20]) == sha3('address2')[:20].encode('hex')
    # assert c.partner(sha3('address2')[:20]) == sha3('address1')[:20].encode('hex')

    # test addrAndDep()
    a1, d1, a2, d2 = c.addrAndDep()
    assert a1 == sha3('address1')[:20].encode('hex')
    assert a2 == sha3('address2')[:20].encode('hex')
    # assert d1 == 30  # failing until we can use deposit in the tests
    # assert d2 == 20  # failing until we can use deposit in the tests
