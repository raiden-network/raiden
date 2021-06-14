import json
from unittest.mock import patch

import pytest
from click.core import ParameterSource  # type: ignore
from click.testing import CliRunner
from requests.exceptions import ConnectionError as RequestsConnectionError, ConnectTimeout

from raiden.accounts import KeystoreAuthenticationError, KeystoreFileNotFound
from raiden.constants import Environment, EthClient, RoutingMode
from raiden.exceptions import (
    APIServerPortInUseError,
    ConfigurationError,
    EthereumNonceTooLow,
    EthNodeInterfaceError,
    RaidenUnrecoverableError,
    ReplacementTransactionUnderpriced,
)
from raiden.network.rpc.middleware import faster_gas_price_strategy
from raiden.tests.utils.cli import assert_invoked_kwargs, get_cli_result, get_invoked_kwargs
from raiden.ui import cli
from raiden.ui.cli import ReturnCode
from raiden.utils.ethereum_clients import VersionSupport, is_supported_client
from raiden.utils.system import get_system_spec


@pytest.fixture
def cli_runner(tmp_path):
    runner = CliRunner(env={"HOME": str(tmp_path)})
    with runner.isolated_filesystem():
        yield runner


def test_cli_version(cli_runner):
    result = cli_runner.invoke(cli.run, ["version"])
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


@pytest.mark.parametrize(
    ("arg_list"),
    [
        ["version", "--short"],
        ["--version"],
    ],
)
def test_cli_version_short(cli_runner, arg_list):
    result = cli_runner.invoke(cli.run, arg_list)
    version = result.output.rstrip()
    expected_short_version = get_system_spec()["raiden"]
    assert version == expected_short_version
    assert result.exit_code == 0


def test_raiden_read_config(tmp_path, cli_runner):

    config = """
        datadir = "~/datadir_from_config_file"
        network-id = 42
        default-reveal-timeout = 21
        [log-config]
        "" = "DEBUG"
        "raiden.network" = "INFO"
        "raiden.transfer" = "WARNING"
        """

    # Config file should exist at the default location (~/.raiden/config.toml)
    datadir = tmp_path / ".raiden"
    datadir.mkdir(parents=True, exist_ok=True)
    config_file = datadir / "config.toml"

    config_file.write_text(config)

    cli_command = "raiden --log-config raiden.transfer:INFO"

    expected_args = {
        # Config file set by default, but path was resolved
        "config_file": (ParameterSource.DEFAULT, str(config_file)),
        # Check mapping of custom internal_name (`network-id` -> `chain_id`)
        "chain_id": (ParameterSource.DEFAULT_MAP, 42),
        "default_reveal_timeout": (ParameterSource.DEFAULT_MAP, 21),
        # Check for merging of config, where CLI takes precedence for loggers
        "log_config": (
            ParameterSource.DEFAULT_MAP,
            {"": "DEBUG", "raiden.network": "INFO", "raiden.transfer": "INFO"},
        ),
        # Letting the config overwrite the datadir AFTER it was read in,
        # does only work when no CLI option for the datadir was given
        "datadir": (ParameterSource.DEFAULT_MAP, str(tmp_path / "datadir_from_config_file")),
    }

    _, kwargs = get_invoked_kwargs(cli_command, cli_runner, "raiden.ui.cli._run")
    assert_invoked_kwargs(kwargs, expected_args)


def test_raiden_defaults(cli_runner, tmp_path):
    # The expected paths will be resolved from home, which is the tmp_path
    datadir = tmp_path / ".raiden"
    datadir.mkdir(parents=True, exist_ok=True)
    config_file = datadir / "config.toml"
    config_file.touch()

    # create an empty config file, otherwise the config file parsers sets the `config_file`
    # kwarg to `None`

    expected_defaults = {
        "datadir": str(datadir),
        "config_file": str(config_file),
        "chain_id": 1,
        "environment_type": Environment.PRODUCTION,
        "accept_disclaimer": False,
        "blockchain_query_interval": 5.0,
        "default_reveal_timeout": 50,
        "default_settle_timeout": 500,
        "sync_check": True,
        "gas_price": faster_gas_price_strategy,
        "eth_rpc_endpoint": "http://127.0.0.1:8545",
        "routing_mode": RoutingMode.PFS,
        "pathfinding_service_address": "auto",
        "pathfinding_max_paths": 3,
        "pathfinding_max_fee": 50000000000000000,
        "pathfinding_iou_timeout": 200000,
        "enable_monitoring": False,
        "matrix_server": "auto",
        "log_config": {"": "INFO"},
        "log_json": False,
        "debug_logfile": True,
        "rpc": True,
        "rpccorsdomain": "http://localhost:*/*",
        "api_address": "127.0.0.1:5001",
        "web_ui": True,
        "switch_tracing": False,
        "unrecoverable_error_should_crash": False,
        "log_memory_usage_interval": 0.0,
        "cap_mediation_fees": True,
        "console": False,
    }

    cli_command = "raiden"

    expected_invoke_kwargs = {
        arg_name: (ParameterSource.DEFAULT, arg_value)
        for arg_name, arg_value in expected_defaults.items()
    }

    _, kwargs = get_invoked_kwargs(cli_command, cli_runner, "raiden.ui.cli._run")
    assert_invoked_kwargs(kwargs, expected_invoke_kwargs)


def test_raiden_disable_on_no_rpc(cli_runner):

    cli_command = "raiden --no-rpc --web-ui --accept-disclaimer"

    expected_invoke_kwargs = {
        "rpc": (ParameterSource.COMMANDLINE, False),
        "web_ui": (ParameterSource.COMMANDLINE, True),
        "accept_disclaimer": (ParameterSource.COMMANDLINE, True),
    }

    # first check the correct invoke options
    _, kwargs = get_invoked_kwargs(cli_command, cli_runner, "raiden.ui.cli._run")
    assert_invoked_kwargs(kwargs, expected_invoke_kwargs)

    # Check for correct warning output
    result = get_cli_result(cli_command, cli_runner, "raiden.ui.cli.run_services")
    expected_output = (
        "RPC has to be enabled (`--rpc` option) for option "
        "`--web-ui`!"
        " Disabling Web-UI option automatically."
    )

    assert expected_output in result.output

    # Check that the web-ui was disabled (after click parsing, but before setting up the
    # config)
    args, _ = get_invoked_kwargs(cli_command, cli_runner, "raiden.ui.cli.run_services")

    call_kwarg_dict = args[0]
    rest_config = call_kwarg_dict["config"].rest_api
    assert call_kwarg_dict["rpc"] is False
    assert call_kwarg_dict["web_ui"] is False

    assert rest_config.rest_api_enabled is False
    assert rest_config.web_ui_enabled is False


@pytest.mark.parametrize(
    ("cli_command", "expected_kwargs"),
    [
        (
            "raiden --accept-disclaimer",
            {
                "enable_monitoring": (ParameterSource.DEFAULT, False),
                "chain_id": (ParameterSource.DEFAULT, 1),
                "accept_disclaimer": (ParameterSource.COMMANDLINE, True),
            },
        ),
        (
            "raiden --no-enable-monitoring --network-id 1 --accept-disclaimer",
            {
                "enable_monitoring": (ParameterSource.COMMANDLINE, False),
                "chain_id": (ParameterSource.COMMANDLINE, 1),
                "accept_disclaimer": (ParameterSource.COMMANDLINE, True),
            },
        ),
    ],
)
def test_no_monitoring_mainnet_warning(cli_runner, cli_command, expected_kwargs):

    _, kwargs = get_invoked_kwargs(cli_command, cli_runner, "raiden.ui.cli._run")
    assert_invoked_kwargs(kwargs, expected_kwargs)

    result = get_cli_result(cli_command, cli_runner, "raiden.ui.cli.run_services")

    expected_output = (
        "WARNING: You did not enable monitoring (`--enable-monitoring`) while "
        "connecting to the Ethereum mainnet.\n"
        "Be aware that you could lose funds when "
        "disconnecting unintentionally!"
    )
    assert expected_output in result.output

    cli_command = "raiden --accept-disclaimer --network-id 42"

    expected_invoke_kwargs = {
        "enable_monitoring": (ParameterSource.DEFAULT, False),
        "chain_id": (ParameterSource.COMMANDLINE, 42),
        "accept_disclaimer": (ParameterSource.COMMANDLINE, True),
    }

    _, kwargs = get_invoked_kwargs(cli_command, cli_runner, "raiden.ui.cli._run")
    assert_invoked_kwargs(kwargs, expected_invoke_kwargs)

    result = get_cli_result(cli_command, cli_runner, "raiden.ui.cli.run_services")

    assert expected_output not in result.output


def test_smoketest_defaults(cli_runner):

    cli_command = "raiden smoketest"

    expected_args = {
        "debug": (ParameterSource.DEFAULT, False),
        "eth_client": (ParameterSource.DEFAULT, EthClient.GETH),
    }

    _, kwargs = get_invoked_kwargs(cli_command, cli_runner, "raiden.ui.cli._smoketest")
    assert_invoked_kwargs(kwargs, expected_args)


def test_smoketest(cli_runner):

    # check debug flag
    cli_command = "raiden smoketest --debug"

    expected_args = {
        "debug": (ParameterSource.COMMANDLINE, True),
    }

    _, kwargs = get_invoked_kwargs(cli_command, cli_runner, "raiden.ui.cli._smoketest")
    assert_invoked_kwargs(kwargs, expected_args)


def test_parent_for_subcommand(cli_runner):

    cli_command = "raiden --environment-type development smoketest"
    _, kwargs = get_invoked_kwargs(cli_command, cli_runner, "raiden.ui.cli._smoketest")

    ctx = kwargs["ctx"]

    assert ctx.parent is not None

    assert ctx.parent.get_parameter_source("environment_type") == ParameterSource.COMMANDLINE
    assert ctx.parent.params["environment_type"] == Environment.DEVELOPMENT


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
        result = cli_runner.invoke(cli.run, "--accept-disclaimer")
        assert result.exception.code == code


def test_check_is_supported_unknown_client():
    supported, client, version = is_supported_client("Aleth//v1.2.1")
    assert supported is VersionSupport.UNSUPPORTED
    assert not client
    assert not version


def run_test_check_json_rpc_geth():
    g1, client, v1 = is_supported_client("Geth/v1.7.3-unstable-e9295163/linux-amd64/go1.9.1")
    g2, _, v2 = is_supported_client("Geth/v1.7.2-unstable-e9295163/linux-amd64/go1.9.1")
    g3, _, v3 = is_supported_client("Geth/v1.8.2-unstable-e9295163/linux-amd64/go1.9.1")
    g4, _, v4 = is_supported_client("Geth/v2.0.3-unstable-e9295163/linux-amd64/go1.9.1")
    g5, _, v5 = is_supported_client("Geth/v11.55.86-unstable-e9295163/linux-amd64/go1.9.1")
    g6, _, v6 = is_supported_client("Geth/v999.999.999-unstable-e9295163/linux-amd64/go1.9.1")
    g8, _, v8 = is_supported_client("Geth/v1.9.0-stable-52f24617/linux-amd64/go1.12.7")
    g9, _, v9 = is_supported_client("Geth/v1.9.0-unstable-3d3e83ec-20190611/linux-amd64/go1.12.5")
    assert client is EthClient.GETH
    assert {g1, g2, g3, g8, g9} == {VersionSupport.SUPPORTED}
    assert {g4, g5, g6} == {VersionSupport.WARN}
    assert v1 == "1.7.3"
    assert v2 == "1.7.2"
    assert v3 == "1.8.2"
    assert v4 == "2.0.3"
    assert v5 == "11.55.86"
    assert v6 == "999.999.999"
    assert v8 == "1.9.0"
    assert v9 == "1.9.0"

    b1, client, v1 = is_supported_client("Geth/v1.7.1-unstable-e9295163/linux-amd64/go1.9.1")
    b2, _, v2 = is_supported_client("Geth/v0.7.1-unstable-e9295163/linux-amd64/go1.9.1")
    b3, _, v3 = is_supported_client("Geth/v0.0.0-unstable-e9295163/linux-amd64/go1.9.1")
    b4, _, _ = is_supported_client("Geth/v0.0.0-unstable-e9295163/linux-amd64/go1.9.1")
    assert client is EthClient.GETH
    assert {b1, b2, b3, b4} == {VersionSupport.UNSUPPORTED}
    assert v1 == "1.7.1"
    assert v2 == "0.7.1"
    assert v3 == "0.0.0"

    supported, client, version = is_supported_client("Geth/faultyversion")
    assert supported is VersionSupport.UNSUPPORTED
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
    g8, _, v8 = is_supported_client(
        "Parity//v2.5.0-stable-19535333c-20171013/x86_64-linux-gnu/rustc1.20.0"
    )
    assert client is EthClient.PARITY
    assert {g1, g2, g3, g8} == {VersionSupport.UNSUPPORTED}
    assert {g4, g5, g6} == {VersionSupport.WARN}
    assert v1 == "1.7.6"
    assert v2 == "1.7.7"
    assert v3 == "1.8.7"
    assert v4 == "2.9.7"
    assert v5 == "23.94.75"
    assert v6 == "99.994.975"
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
    assert {b1, b2, b3, b4, b5} == {VersionSupport.UNSUPPORTED}
    assert v1 == "1.7.5"
    assert v2 == "1.5.1"
    assert v3 == "0.7.1"
    assert v4 == "0.8.7"
    assert v5 == "0.0.0"

    supported, client, version = is_supported_client("Parity//faultyversion")
    assert supported is VersionSupport.UNSUPPORTED
    assert not client
    assert not version


def test_check_json_rpc_parity():
    # Pin the highest supported version for the test purposes
    with patch("raiden.utils.ethereum_clients.HIGHEST_SUPPORTED_PARITY_VERSION", new="2.5.5"):
        run_test_check_json_rpc_parity()
