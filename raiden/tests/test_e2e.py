# -*- coding: utf8 -*-
import pytest
import gevent.monkey
from ethereum import slogging
from raiden.tests.utils.transfer import direct_transfer, mediated_transfer

# Monkey patch subprocess.Popen used by solidity wrapper
gevent.monkey.patch_socket()  # patch_subprocess()
slogging.configure(':ERROR,eth.chain.tx:DEBUG,jsonrpc:DEBUG,eth.vm:TRACE')

from pyethapp.utils import enable_greenlet_debugger
enable_greenlet_debugger()


@pytest.mark.xfail(reason='flaky test')  # this test has timeout issues that need to be fixed
@pytest.mark.parametrize('privatekey_seed', ['fullnetwork:{}'])
@pytest.mark.parametrize('number_of_nodes', [3])
@pytest.mark.parametrize('timeout', [3])
def test_fullnetwork(deployed_network):
    app0, app1, app2 = deployed_network  # pylint: disable=unbalanced-tuple-unpacking

    asset_address = app0.raiden.chain.asset_addresses[0]

    amount = 80
    direct_transfer(app0, app1, asset_address, amount)

    amount = 50
    direct_transfer(app1, app2, asset_address, amount)

    amount = 30
    mediated_transfer(app1, app2, asset_address, amount)
