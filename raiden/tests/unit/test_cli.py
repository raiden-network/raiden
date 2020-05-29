import json
from functools import partial
from unittest.mock import patch

import pytest
from click.testing import CliRunner
from requests.exceptions import ConnectionError as RequestsConnectionError, ConnectTimeout

from raiden.accounts import KeystoreAuthenticationError, KeystoreFileNotFound
from raiden.constants import EthClient
from raiden.exceptions import (
    APIServerPortInUseError,
    ConfigurationError,
    EthereumNonceTooLow,
    EthNodeInterfaceError,
    RaidenUnrecoverableError,
    ReplacementTransactionUnderpriced,
)
from raiden.ui import cli
from raiden.ui.cli import ReturnCode
from raiden.utils.ethereum_clients import is_supported_client


@pytest.fixture
def cli_runner(tmp_path):
    runner = CliRunner()
    with runner.isolated_filesystem():
        yield partial(runner.invoke, env={"HOME": str(tmp_path)})


def test_cli_version(cli_runner):
    result = cli_runner(cli.run, ["version"])
    result_json = json.loads(result.output)
    result_expected_keys = {
        "raiden",
        "raiden_db_version",
        "python_implementation",
        "python_version",
        "system",
        "architecture",
        "distribution",
    }
    assert result_expected_keys == result_json.keys()
    assert result.exit_code == 0


def mock_raises(exception):
    def f(*_, **__):
        raise exception

    return f


def test_run_error_reporting(cli_runner, monkeypatch):
    caught_exceptions = {
        APIServerPortInUseError(): ReturnCode.PORT_ALREADY_IN_USE,
        ConfigurationError(): ReturnCode.RAIDEN_CONFIGURATION_ERROR,
        ConnectTimeout(): ReturnCode.GENERIC_COMMUNICATION_ERROR,
        ConnectionError(): ReturnCode.GENERIC_COMMUNICATION_ERROR,
        EthereumNonceTooLow(): ReturnCode.ETH_ACCOUNT_ERROR,
        EthNodeInterfaceError(): ReturnCode.ETH_INTERFACE_ERROR,
        KeystoreAuthenticationError(): ReturnCode.ETH_ACCOUNT_ERROR,
        KeystoreFileNotFound(): ReturnCode.ETH_ACCOUNT_ERROR,
        RaidenUnrecoverableError(): ReturnCode.FATAL,
        ReplacementTransactionUnderpriced(): ReturnCode.ETH_ACCOUNT_ERROR,
        RequestsConnectionError(): ReturnCode.GENERIC_COMMUNICATION_ERROR,
        Exception(): ReturnCode.FATAL,
    }

    for exception, code in caught_exceptions.items():
        monkeypatch.setattr(cli, "run_services", mock_raises(exception))
        result = cli_runner(cli.run, "--accept-disclaimer")
        assert result.exception.code == code


def test_check_is_supported_unknown_client():
    supported, client, version = is_supported_client("Aleth//v1.2.1")
    assert not supported
    assert not client
    assert not version


def run_test_check_json_rpc_geth():
    g1, client, v1 = is_supported_client("Geth/v1.7.3-unstable-e9295163/linux-amd64/go1.9.1")
    g2, _, v2 = is_supported_client("Geth/v1.7.2-unstable-e9295163/linux-amd64/go1.9.1")
    g3, _, v3 = is_supported_client("Geth/v1.8.2-unstable-e9295163/linux-amd64/go1.9.1")
    g4, _, v4 = is_supported_client("Geth/v2.0.3-unstable-e9295163/linux-amd64/go1.9.1")
    g5, _, v5 = is_supported_client("Geth/v11.55.86-unstable-e9295163/linux-amd64/go1.9.1")
    g6, _, v6 = is_supported_client("Geth/v999.999.999-unstable-e9295163/linux-amd64/go1.9.1")
    # Test that patch version upgrades are not triggering the non-supported check
    g7, _, v7 = is_supported_client("Geth/v1.9.3-unstable-e9295163/linux-amd64/go1.9.1")
    g8, _, v8 = is_supported_client("Geth/v1.9.0-stable-52f24617/linux-amd64/go1.12.7")
    g9, _, v9 = is_supported_client("Geth/v1.9.0-unstable-3d3e83ec-20190611/linux-amd64/go1.12.5")
    assert client is EthClient.GETH
    assert all([g1, g2, g3, g7, g8, g9])
    assert not any([g4, g5, g6])
    assert v1 == "1.7.3"
    assert v2 == "1.7.2"
    assert v3 == "1.8.2"
    assert v4 == "2.0.3"
    assert v5 == "11.55.86"
    assert v6 == "999.999.999"
    assert v7 == "1.9.3"
    assert v8 == "1.9.0"
    assert v9 == "1.9.0"

    b1, client, v1 = is_supported_client("Geth/v1.7.1-unstable-e9295163/linux-amd64/go1.9.1")
    b2, _, v2 = is_supported_client("Geth/v0.7.1-unstable-e9295163/linux-amd64/go1.9.1")
    b3, _, v3 = is_supported_client("Geth/v0.0.0-unstable-e9295163/linux-amd64/go1.9.1")
    b4, _, _ = is_supported_client("Geth/v0.0.0-unstable-e9295163/linux-amd64/go1.9.1")
    assert client is EthClient.GETH
    assert not any([b1, b2, b3, b4])
    assert v1 == "1.7.1"
    assert v2 == "0.7.1"
    assert v3 == "0.0.0"

    supported, client, version = is_supported_client("Geth/faultyversion")
    assert not supported
    assert not client
    assert not version


def test_check_json_rpc_geth():
    # Pin the highest supported version for the test purposes
    with patch("raiden.utils.ethereum_clients.HIGHEST_SUPPORTED_GETH_VERSION", new="1.9.2"), patch(
        "raiden.utils.ethereum_clients.LOWEST_SUPPORTED_GETH_VERSION", new="1.7.2"
    ):
        run_test_check_json_rpc_geth()


def run_test_check_json_rpc_parity():
    g1, client, v1 = is_supported_client(
        "Parity//v1.7.6-stable-19535333c-20171013/x86_64-linux-gnu/rustc1.20.0"
    )
    g2, _, v2 = is_supported_client(
        "Parity//v1.7.7-stable-19535333c-20171013/x86_64-linux-gnu/rustc1.20.0"
    )
    g3, _, v3 = is_supported_client(
        "Parity/v1.8.7-stable-19535333c-20171013/x86_64-linux-gnu/rustc1.20.0"
    )
    g4, _, v4 = is_supported_client(
        "Parity//v2.9.7-stable-19535333c-20171013/x86_64-linux-gnu/rustc1.20.0"
    )
    g5, _, v5 = is_supported_client(
        "Parity/v23.94.75-stable-19535333c-20171013/x86_64-linux-gnu/rustc1.20.0"
    )
    g6, _, v6 = is_supported_client(
        "Parity//v99.994.975-stable-19535333c-20171013/x86_64-linux-gnu/rustc1.20.0"
    )
    # Test that patch version upgrades are not triggering the non-supported check
    g7, _, v7 = is_supported_client(
        "Parity//v2.5.8-stable-19535333c-20171013/x86_64-linux-gnu/rustc1.20.0"
    )
    g8, _, v8 = is_supported_client(
        "Parity//v2.5.0-stable-19535333c-20171013/x86_64-linux-gnu/rustc1.20.0"
    )
    assert client is EthClient.PARITY
    assert all([g1, g2, g3, g7, g8])
    assert not any([g4, g5, g6])
    assert v1 == "1.7.6"
    assert v2 == "1.7.7"
    assert v3 == "1.8.7"
    assert v4 == "2.9.7"
    assert v5 == "23.94.75"
    assert v6 == "99.994.975"
    assert v7 == "2.5.8"
    assert v8 == "2.5.0"

    b1, client, v1 = is_supported_client(
        "Parity//v1.7.5-stable-19535333c-20171013/x86_64-linux-gnu/rustc1.20.0"
    )
    b2, _, v2 = is_supported_client(
        "Parity/v1.5.1-stable-19535333c-20171013/x86_64-linux-gnu/rustc1.20.0"
    )
    b3, _, v3 = is_supported_client(
        "Parity//v0.7.1-stable-19535333c-20171013/x86_64-linux-gnu/rustc1.20.0"
    )
    b4, _, v4 = is_supported_client(
        "Parity/v0.8.7-stable-19535333c-20171013/x86_64-linux-gnu/rustc1.20.0"
    )
    b5, _, v5 = is_supported_client(
        "Parity//v0.0.0-stable-19535333c-20171013/x86_64-linux-gnu/rustc1.20.0"
    )
    assert client is EthClient.PARITY
    assert not any([b1, b2, b3, b4, b5])
    assert v1 == "1.7.5"
    assert v2 == "1.5.1"
    assert v3 == "0.7.1"
    assert v4 == "0.8.7"
    assert v5 == "0.0.0"

    supported, client, version = is_supported_client("Parity//faultyversion")
    assert not supported
    assert not client
    assert not version


def test_check_json_rpc_parity():
    # Pin the highest supported version for the test purposes
    with patch("raiden.utils.ethereum_clients.HIGHEST_SUPPORTED_PARITY_VERSION", new="2.5.5"):
        run_test_check_json_rpc_parity()
