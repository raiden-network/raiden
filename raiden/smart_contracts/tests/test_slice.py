# -*- coding: utf8 -*-
import pytest

from ethereum import tester
from ethereum.tester import TransactionFailed

slicer_code = open("raiden/smart_contracts/Slicer.sol").read()

def test_slice():
    s = tester.state()
    c = s.abi_contract(slicer_code, language="solidity")
    o2 = c.slice("hello", 0, 2)
    assert o2.decode('utf-8') == "he"
    o2 = c.slice("hello", 0, 5)
    assert o2.decode('utf-8') == "hello"
    # should throw on invalid input
    with pytest.raises(TransactionFailed):
        c.slice("hello", 5, 8)
