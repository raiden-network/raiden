import json
from functools import partial

import pytest
from click.testing import CliRunner

from raiden.constants import EthClient
from raiden.ui.cli import OPTION_DEPENDENCIES, run
from raiden.utils import is_minified_address, is_supported_client

# Values to be used to test the option dependencies, need to be distinct form the default values
# The tuples define the inverse values for the depended-on options
_OPTION_DEPENDENCY_TEST_VALUES = {
    'pathfinding-service-address': 'https://example.com',
    'enable-monitoring': None,
    'matrix-server': 'https://example.com',
    'listen-address': '0.0.0.0:5001',
    'max-unresponsive-time': 100,
    'send-ping-time': 100,
    'nat': 'stun',
    ('transport', 'matrix'): 'udp',
    ('transport', 'udp'): 'matrix',
}


@pytest.fixture
def cli_runner(tmp_path):
    runner = CliRunner()
    with runner.isolated_filesystem():
        yield partial(runner.invoke, env={'HOME': str(tmp_path)})


def pytest_generate_tests(metafunc):
    if metafunc.definition.name == 'test_cli_option_dependencies':
        test_params = []
        test_ids = []
        for option_name, dependencies in OPTION_DEPENDENCIES.items():
            args = [f'--{option_name}']
            option_test_value = _OPTION_DEPENDENCY_TEST_VALUES.get(option_name)
            if option_test_value is not None:
                args.append(option_test_value)

            for dep_name, dep_value in dependencies:
                args.append(f'--{dep_name}')
                dep_test_value = _OPTION_DEPENDENCY_TEST_VALUES.get((dep_name, dep_value))
                args.append(dep_test_value)

                error_message = (
                    f'This option is only available when option "--{dep_name}" '
                    f'is set to "{dep_value}". Current value: "{dep_test_value}"'
                )
                # Only test first depended-on option for now
                # TODO: Implement multiple option dependencies test when such an option is added
                break
            test_params.append((args, error_message))
            test_ids.append(option_name)
        metafunc.parametrize(('args', 'error_message'), test_params, ids=test_ids)


# This is parametrized via `pytest_generate_tests` above
def test_cli_option_dependencies(cli_runner, args, error_message):
    result = cli_runner(run, args)
    assert error_message in result.output
    assert result.exit_code == 2


def test_cli_version(cli_runner):
    result = cli_runner(run, ['version'])
    result_json = json.loads(result.output)
    result_expected_keys = [
        'raiden',
        'python_implementation',
        'python_version',
        'system',
        'distribution',
    ]
    for expected_key in result_expected_keys:
        assert expected_key in result_json
    assert result.exit_code == 0


def test_check_json_rpc_geth():
    g1, client = is_supported_client('Geth/v1.7.3-unstable-e9295163/linux-amd64/go1.9.1')
    g2, _ = is_supported_client('Geth/v1.7.2-unstable-e9295163/linux-amd64/go1.9.1')
    g3, _ = is_supported_client('Geth/v1.8.2-unstable-e9295163/linux-amd64/go1.9.1')
    g4, _ = is_supported_client('Geth/v2.0.3-unstable-e9295163/linux-amd64/go1.9.1')
    g5, _ = is_supported_client('Geth/v11.55.86-unstable-e9295163/linux-amd64/go1.9.1')
    g6, _ = is_supported_client('Geth/v999.999.999-unstable-e9295163/linux-amd64/go1.9.1')
    assert client == EthClient.GETH
    assert all([g1, g2, g3, g4, g5, g6])

    b1, client = is_supported_client('Geth/v1.7.1-unstable-e9295163/linux-amd64/go1.9.1')
    b2, _ = is_supported_client('Geth/v0.7.1-unstable-e9295163/linux-amd64/go1.9.1')
    b3, _ = is_supported_client('Geth/v0.0.0-unstable-e9295163/linux-amd64/go1.9.1')
    b4, _ = is_supported_client('Geth/v0.0.0-unstable-e9295163/linux-amd64/go1.9.1')
    assert not client
    assert not any([b1, b2, b3, b4])


def test_check_json_rpc_parity():
    g1, client = is_supported_client(
        'Parity//v1.7.6-stable-19535333c-20171013/x86_64-linux-gnu/rustc1.20.0',
    )
    g2, _ = is_supported_client(
        'Parity//v1.7.7-stable-19535333c-20171013/x86_64-linux-gnu/rustc1.20.0',
    )
    g3, _ = is_supported_client(
        'Parity//v1.8.7-stable-19535333c-20171013/x86_64-linux-gnu/rustc1.20.0',
    )
    g4, _ = is_supported_client(
        'Parity//v2.9.7-stable-19535333c-20171013/x86_64-linux-gnu/rustc1.20.0',
    )
    g5, _ = is_supported_client(
        'Parity//v23.94.75-stable-19535333c-20171013/x86_64-linux-gnu/rustc1.20.0',
    )
    g6, _ = is_supported_client(
        'Parity//v99.994.975-stable-19535333c-20171013/x86_64-linux-gnu/rustc1.20.0',
    )
    assert client == EthClient.PARITY
    assert all([g1, g2, g3, g4, g5, g6])

    b1, client = is_supported_client(
        'Parity//v1.7.5-stable-19535333c-20171013/x86_64-linux-gnu/rustc1.20.0',
    )
    b2, _ = is_supported_client(
        'Parity//v1.5.1-stable-19535333c-20171013/x86_64-linux-gnu/rustc1.20.0',
    )
    b3, _ = is_supported_client(
        'Parity//v0.7.1-stable-19535333c-20171013/x86_64-linux-gnu/rustc1.20.0',
    )
    b4, _ = is_supported_client(
        'Parity//v0.8.7-stable-19535333c-20171013/x86_64-linux-gnu/rustc1.20.0',
    )
    b5, _ = is_supported_client(
        'Parity//v0.0.0-stable-19535333c-20171013/x86_64-linux-gnu/rustc1.20.0',
    )
    assert not client
    assert not any([b1, b2, b3, b4, b5])


def test_minified_address_checker():
    assert is_minified_address('9bed7fd1')
    assert is_minified_address('8c1d1f23')
    assert not is_minified_address('xxxxxx')
    assert not is_minified_address('123zzz')
    assert not is_minified_address('$@$^$')
