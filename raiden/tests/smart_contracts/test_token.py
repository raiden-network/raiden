# -*- coding: utf8 -*-
from ethereum import tester

from raiden.blockchain.abi import get_contract_path


def test_ncc():
    token_library_path = get_contract_path('StandardToken.sol')
    token_path = get_contract_path('HumanStandardToken.sol')

    state = tester.state()

    assert state.block.number < 1150000
    state.block.number = 1158001
    assert state.block.number > 1150000

    token = state.abi_contract(
        None,
        path=token_library_path,
        language='solidity',
    )

    contract_libraries = {
        'StandardToken': token.address.encode('hex'),
    }
    contract = state.abi_contract(
        None,
        path=token_path,
        language='solidity',
        libraries=contract_libraries,
        constructor_parameters=[10000, 'raiden', 0, 'rd'],
    )

    # pylint: disable=no-member
    assert contract.balanceOf(tester.a0) == 10000
    assert contract.balanceOf(tester.a1) == 0
    assert contract.transfer(tester.a1, 5000) is True
    assert contract.balanceOf(tester.a0) == 5000
    assert contract.balanceOf(tester.a1) == 5000
