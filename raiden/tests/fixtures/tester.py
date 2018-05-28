# -*- coding: utf-8 -*-
import pytest

from raiden.tests.utils.tester import create_tester_chain


@pytest.fixture
def tester_blockgas_limit():
    """ The tester's block gas limit.

    Set this value to `GAS_LIMIT` if the test needs to consider the gas usage.

    Note:
        `GAS_LIMIT` is defined in `raiden.network.rpc.client.GAS_LIMIT`
    """
    return 10 ** 10


@pytest.fixture
def tester_chain(deploy_key, private_keys, tester_blockgas_limit):
    return create_tester_chain(deploy_key, private_keys, tester_blockgas_limit)
