# -*- coding: utf8 -*-
import pytest
from ethereum import utils
from ethereum import tester
from ethereum.utils import sha3, privtoaddr
from ethereum.tester import TransactionFailed

ncc_path = "raiden/smart_contracts/NettingChannelContract.sol"


def test_ncc():
    s = tester.state()
    assert s.block.number < 1150000
    s.block.number = 1158001
    assert s.block.number > 1150000
    c = s.abi_contract(None, path=ncc_path, language="solidity", constructor_parameters=[sha3('assetAddress')[:20], sha3('address1')[:20], sha3('address2')[:20], 30])

    # # test global variables
    # assert c.lockedTime == 30
    # assert c.assetAddress == sha3('assetAddress')[:20].encode('hex')
    # assert c.opened == 0
    # assert c.closed == 0
    # assert c.settled == 0
    # assert c.closingAddress == ''

    # # test participants variables changed when constructing
    # assert c.participants[0].addr == sha3('address1')[:20]
    # assert c.participants[1].addr == sha3('address2')[:20]

    # # test atIndex()
    # assert c.atIndex(sha3('address1')[:20]) == 0
    # assert c.atIndex(sha3('address2')[:20]) == 1

    # # test deposit(uint)
    # c.deposit(30)
    # # TODO need to add HumanToken support in order for this to work

    # # test open()
    # assert c.opened == 0  # channel is not yet opened
    # c.open()
    # assert c.opened > 0
    # assert c.opened <= s.block.number

    # # test partner(address)
    # assert c.partner(sha3('address1')[:20]) == sha3('address2')[:20].encode('hex')
    # assert c.partner(sha3('address2')[:20]) == sha3('address1')[:20].encode('hex')

    # # test addrAndDep()
    # a1, d1, a2, d2 = c.addrAndDep()
    # assert a1 == sha3('address1')[:20]
    # assert a2 == sha3('address2')[:20]
    # assert d1 == 30
    # assert d2 == 20
