# -*- coding: utf8 -*-
import pytest


@pytest.fixture
def settle_timeout():
    """ NettingChannel default settle timeout. """
    return DEFAULT_SETTLE_TIMEOUT


@pytest.fixture
def asset_amount():
    """ Default asset amount. """
    return 10000


@pytest.fixture
def asset():
    """ Default asset address. """
    return sha3('asset')[:20]


@pytest.fixture
def deposit():
    """ Raiden chain default deposit. """
    return DEFAULT_DEPOSIT


@pytest.fixture
def number_of_assets():
    """ Number of assets created. """
    return 1


@pytest.fixture
def assets_addresses(number_of_assets):
    return [
        sha3('asset:{}'.format(number))[:20]
        for number in range(number_of_assets)
    ]


@pytest.fixture
def privatekey_seed():
    """ Private key template, allow different keys to be used for each test to
    avoid collisions.
    """
    return 'key:{}'


@pytest.fixture
def private_keys(number_of_nodes, privatekey_seed):
    """ Private keys for each raiden node. """
    return [
        sha3(privatekey_seed.format(position))
        for position in range(number_of_nodes)
    ]
