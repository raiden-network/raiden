# -*- coding: utf8 -*-
import pytest

from ethereum import utils
from ethereum import tester
from ethereum.utils import sha3, privtoaddr
from ethereum.tester import TransactionFailed

# from raiden.network.rpc.client import get_contract_path

token_library_path = "raiden/smart_contracts/StandardToken.sol"
token_path = "raiden/smart_contracts/HumanStandardToken.sol"

# library_path = get_contract_path('Decoder.sol')
library_path = "raiden/smart_contracts/Decoder.sol"
# ncc_path = get_contract_path('NettingChannelContract.sol.old')
ncc_path = "raiden/smart_contracts/NettingChannelContract.sol.old"

# tester.gas_limit = 9575081L

def test_ncc():
    s = tester.state()
    assert s.block.number < 1150000
    s.block.number = 1158001
    assert s.block.number > 1150000
    # Token creation
    lib_token = s.abi_contract(None, path=token_library_path, language="solidity")
    token = s.abi_contract(None, path=token_path, language="solidity", libraries={'StandardToken': lib_token.address.encode('hex')}, constructor_parameters=[10000, "raiden", 0, "rd"])

    s.mine()

    lib_c = s.abi_contract(None, path=library_path, language="solidity")
    s.mine()
    c = s.abi_contract(None, path=ncc_path, language="solidity", libraries={'Decoder': lib_c.address.encode('hex')}, constructor_parameters=[token.address, tester.a0, tester.a1, 30])

    # test tokens and distribute tokens
    assert token.balanceOf(tester.a0) == 10000
    assert token.balanceOf(tester.a1) == 0
    assert token.transfer(tester.a1, 5000) == True
    assert token.balanceOf(tester.a0) == 5000
    assert token.balanceOf(tester.a1) == 5000

    # test global variables
    assert c.lockedTime() == 30
    assert c.assetAddress() == token.address.encode('hex')
    assert c.opened() == 0
    assert c.closed() == 0
    assert c.settled() == 0

    # test participants variables changed when constructing
    assert c.participants(0)[0] == tester.a0.encode('hex')
    assert c.participants(1)[0] == tester.a1.encode('hex')

    # test atIndex()
    # private must be removed from the function in order to work
    # assert c.atIndex(sha3('address1')[:20]) == 0
    # assert c.atIndex(sha3('address2')[:20]) == 1

    # test deposit(uint)
    assert token.balanceOf(c.address) == 0
    assert token.approve(c.address, 30) == True # allow the contract do deposit
    assert c.participants(0)[1] == 0
    with pytest.raises(TransactionFailed):
        c.deposit(5001)
    c.deposit(30)
    assert c.participants(0)[1] == 30
    assert token.balanceOf(c.address) == 30
    assert token.balanceOf(tester.a0) == 4970
    assert c.opened() == s.block.number

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
    assert a1 == tester.a0.encode('hex')
    assert a2 == tester.a1.encode('hex')
    assert d1 == 30
    assert d2 == 0
