import logging
import os
from unittest.mock import DEFAULT, Mock, patch

from click.testing import CliRunner
from eth_utils import is_checksum_address
from web3 import Web3

from pathfinding_service.cli import get_default_registry_and_start_block, main

patch_args = dict(
    target='pathfinding_service.cli',
    PathfindingService=DEFAULT,
    ServiceApi=DEFAULT,
    HTTPProvider=DEFAULT,
    get_default_registry_and_start_block=DEFAULT,
)


def test_bad_eth_client(caplog):
    """ Giving a bad `eth-rpc` value should yield a concise error message """
    runner = CliRunner()
    with patch('pathfinding_service.cli.PathfindingService'):
        result = runner.invoke(main, ['--eth-rpc', 'http://localhost:12345'])
    assert result.exit_code == 1
    assert 'Can not connect to the Ethereum client' in caplog.records[0].getMessage()


def test_success():
    """ Calling the pathfinding_service with default args should succeed after heavy mocking """
    runner = CliRunner()
    with patch.multiple(**patch_args) as mocks:
        mocks['get_default_registry_and_start_block'].return_value = Mock(), Mock()
        result = runner.invoke(main, [])
    assert result.exit_code == 0


def test_eth_rpc():
    """ The `eth-rpc` parameter must reach the `HTTPProvider` """
    runner = CliRunner()
    eth_rpc = 'example.com:1234'
    with patch('pathfinding_service.cli.HTTPProvider') as provider:
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
        result = runner.invoke(main, [
            '--registry-address', address, '--start-block', str(start_block)],
        )
        assert result.exit_code == 0
        assert mocks['PathfindingService'].call_args[1]['sync_start_block'] == start_block


def test_confirmations():
    """ The `confirmations` parameter must reach the `PathfindingService` """
    runner = CliRunner()
    with patch.multiple(**patch_args) as mocks:
        mocks['get_default_registry_and_start_block'].return_value = Mock(), Mock()
        confirmations = 77
        result = runner.invoke(main, [
            '--confirmations', str(confirmations)], catch_exceptions=False,
        )
        assert result.exit_code == 0
        assert mocks['PathfindingService'].call_args[1]['required_confirmations'] == confirmations


def test_default_registry(token_network_registry_contract):
    """ We can fall back to a default registry if none if specified """
    net_version = 3
    contracts_version = 'pre_limits'
    registry_address, block_number = get_default_registry_and_start_block(
        net_version,
        contracts_version,
    )
    assert is_checksum_address(registry_address)
    assert block_number > 0


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


def test_log_level():
    """ Setting of log level via command line switch """
    runner = CliRunner()
    with patch.multiple(**patch_args), \
            patch('pathfinding_service.cli.logging.basicConfig') as basicConfig:
        for log_level in ('CRITICAL', 'WARNING'):
            runner.invoke(main, ['--log-level', log_level])
            # pytest already initializes logging, so basicConfig does not have
            # an effect. Use mocking to check that it's called properly.
            assert logging.getLevelName(
                basicConfig.call_args[1]['level'] == log_level,
            )


def test_log_config(tmp_path):
    """ Detailed setting of logging via config file """
    conf_filename = os.path.join(tmp_path, 'log-conf.json')
    with open(conf_filename, 'w') as f:
        f.write("""{
            "version": 1,
            "loggers": {
                "web3": {
                    "level": "ERROR"
                }
            }
        }""")
    runner = CliRunner()
    with patch.multiple(**patch_args) as mocks:
        mocks['get_default_registry_and_start_block'].return_value = Mock(), Mock()
        runner.invoke(main, ['--log-config', conf_filename], catch_exceptions=False)
        assert logging.getLevelName(
            logging.getLogger('web3').getEffectiveLevel(),
        ) == 'ERROR'
