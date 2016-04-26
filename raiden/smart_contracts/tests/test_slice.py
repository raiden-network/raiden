# -*- coding: utf8 -*-
import pytest

from ethereum import tester
from ethereum.tester import TransactionFailed

slicer_code = '''
    contract Slicer {

        function slice(bytes a, uint start, uint end) returns (bytes n) {
            if (a.length < end) throw;
            if (start < 0) throw;
            if (start > end) throw;
            n = new bytes(end-start);
            for ( uint i = start; i < end; i ++) { //python style slice
                n[i-start] = a[i];
            }
        }
    }
'''


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
