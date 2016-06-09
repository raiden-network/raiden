# -*- coding: utf8 -*-
import pytest

from ethereum import utils
from ethereum import tester
from ethereum.utils import sha3, privtoaddr
from ethereum.tester import TransactionFailed

token_library_path = "raiden/smart_contracts/StandardToken.sol"
token_path = "raiden/smart_contracts/HumanStandardToken.sol"


def test_ncc():
    s = tester.state()
    assert s.block.number < 1150000
    s.block.number = 1158001
    assert s.block.number > 1150000
    lib_c = s.abi_contract(None, path=token_library_path, language="solidity")
    c = s.abi_contract(None, path=token_path, language="solidity", libraries={'StandardToken': lib_c.address.encode('hex')}, constructor_parameters=[10000, "raiden", 0, "rd"])

    assert c.balanceOf(tester.a0) == 10000
    assert c.balanceOf(tester.a1) == 0
    assert c.transfer(tester.a1, 5000) == True
    assert c.balanceOf(tester.a0) == 5000
    assert c.balanceOf(tester.a1) == 5000
