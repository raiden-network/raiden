# -*- coding: utf8 -*-
import pytest
from ethereum import utils
from ethereum import tester
from ethereum.utils import sha3, privtoaddr
from ethereum.tester import TransactionFailed

ncc_code = open("raiden/smart_contracts/nettingChannelContract.sol").read()

def test_ncc():
    s = tester.state()
    assert s.block.number < 1150000
    s.block.number = 1158001
    assert s.block.number > 1150000
    c = s.abi_contract(ncc_code, language="solidity")


    
