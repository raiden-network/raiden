# -*- coding: utf8 -*-
import pytest

from ethereum import tester
from ethereum.tester import TransactionFailed

from raiden.network.rpc.client import get_contract_path


def test_slice():
    slicer_path = get_contract_path('Slicer.sol')

    with open(slicer_path) as slicer_file:
        slicer_code = slicer_file.read()

    state = tester.state()
    slicer = state.abi_contract(slicer_code, language='solidity')

    # pylint: disable=no-member
    assert slicer.slice('hello', 0, 2).decode('utf-8') == 'he'
    assert slicer.slice('hello', 0, 5).decode('utf-8') == 'hello'

    # should throw on invalid input
    with pytest.raises(TransactionFailed):
        slicer.slice('hello', 5, 8)
