from unittest.mock import DEFAULT, Mock, patch

import pytest
from click.testing import CliRunner
from web3 import Web3

from pathfinder.cli import get_default_registry_and_start_block, main

patch_args = dict(
    target='pathfinder.cli',
    PathfindingService=DEFAULT,
    ServiceApi=DEFAULT,
    HTTPProvider=DEFAULT,
    get_default_registry_and_start_block=DEFAULT,
)


def test_bad_eth_client(caplog):
    """ Giving a bad `eth-rpc` value should yield a concise error message """
    runner = CliRunner()
    with patch('pathfinder.cli.PathfindingService'):
        result = runner.invoke(main, ['--eth-rpc', 'http://localhost:12345'])
    assert result.exit_code == 1
    assert 'Can not connect to the Ethereum client' in caplog.records[0].getMessage()


def test_success():
    """ Calling the pathfinder with default args should succeed after heavy mocking """
    runner = CliRunner()
    with patch.multiple(**patch_args) as mocks:
        mocks['get_default_registry_and_start_block'].return_value = Mock(), Mock()
        result = runner.invoke(main, [])
    assert result.exit_code == 0


def test_eth_rpc():
    """ The `eth-rpc` parameter must reach the `HTTPProvider` """
    runner = CliRunner()
    eth_rpc = 'example.com:1234'
    with patch('pathfinder.cli.HTTPProvider') as provider:
        runner.invoke(main, ['--eth-rpc', eth_rpc])
        provider.assert_called_with(eth_rpc)


def test_registry_address():
    """ The `registry_address` parameter must reach the `PathfindingService` """
    runner = CliRunner()
    with patch.multiple(**patch_args) as mocks:
        address = Web3.toChecksumAddress('0x' + '1' * 40)
        result = runner.invoke(main, ['--registry-address', address])
        assert result.exit_code == 0
        assert mocks['PathfindingService'].call_args[1]['registry_address'] == address

    # check validation of address format
    def fails_on_registry_check(address):
        result = runner.invoke(main, ['--registry-address', address], catch_exceptions=False)
        assert result.exit_code != 0
        assert 'EIP-55' in result.output

    fails_on_registry_check('1' * 40)  # no 0x
    fails_on_registry_check('0x' + '1' * 41)  # not 40 digits
    fails_on_registry_check('0x' + '1' * 39)  # not 40 digits


def test_start_block():
    """ The `start_block` parameter must reach the `PathfindingService`

    We also have to pass a registry address, because `start_block` is
    overwritten with a default when no registry has been specified.
    """
    runner = CliRunner()
    with patch.multiple(**patch_args) as mocks:
        mocks['get_default_registry_and_start_block'].return_value = Mock(), Mock()
        start_block = 10
        address = Web3.toChecksumAddress('0x' + '1'*40)
        result = runner.invoke(main, ['--registry-address', address, '--start-block', start_block])
        assert result.exit_code == 0
        assert mocks['PathfindingService'].call_args[1]['sync_start_block'] == start_block


def test_confirmations():
    """ The `confirmations` parameter must reach the `PathfindingService` """
    runner = CliRunner()
    with patch.multiple(**patch_args) as mocks:
        mocks['get_default_registry_and_start_block'].return_value = Mock(), Mock()
        confirmations = 77
        result = runner.invoke(main, ['--confirmations', confirmations], catch_exceptions=False)
        assert result.exit_code == 0
        assert mocks['PathfindingService'].call_args[1]['required_confirmations'] == confirmations


@pytest.mark.skip  # TODO: add a fixture provides the required contracts
def test_default_registry(web3):
    """ We can fall back to a default registry if none if specified """
    net_version = int(web3.net.version)
    contracts_version = 'pre_limits'
    registry_address, block_number = get_default_registry_and_start_block(
            net_version,
            contracts_version,
    )


def test_shutdown():
    """ Clean shutdown after KeyboardInterrupt """
    runner = CliRunner()
    with patch.multiple(**patch_args) as mocks:
        mocks['get_default_registry_and_start_block'].return_value = Mock(), Mock()
        mocks['PathfindingService'].return_value.run.side_effect = KeyboardInterrupt
        result = runner.invoke(main, [], catch_exceptions=False)
        assert result.exit_code == 0
        assert 'Exiting' in result.output
        assert mocks['PathfindingService'].return_value.stop.called
        assert mocks['ServiceApi'].return_value.stop.called
