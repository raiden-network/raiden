import json
import sys

import pexpect
import pytest
from click.testing import CliRunner
from eth_utils import to_checksum_address

from raiden.constants import Environment
from raiden.ui.cli import OPTION_DEPENDENCIES, run

EXPECTED_DEFAULT_ENVIRONMENT_VALUE = Environment.PRODUCTION.value


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


def spawn_raiden(args):
    return pexpect.spawn(
        sys.executable, ['-m', 'raiden'] + args,
        logfile=sys.stdout,
        encoding='utf-8',
    )


def expect_cli_until_acknowledgment(child):
    child.expect('Welcome to Raiden')
    child.expect('Have you read, understood and hereby accept the above')
    child.sendline('y')


def expect_cli_until_account_selection(child):
    expect_cli_until_acknowledgment(child)
    child.expect('The following accounts were found in your machine:')
    child.expect('Select one of them by index to continue: ')
    child.sendline('0')


def expect_cli_successful_connected(child, mode):
    child.expect(f'Raiden is running in {mode} mode')
    child.expect('You are connected')
    child.expect('The Raiden API RPC server is now running')


def expect_cli_normal_startup(child, mode):
    expect_cli_until_acknowledgment(child)
    expect_cli_until_account_selection(child)
    expect_cli_successful_connected(child, mode)


def test_cli_version():
    runner = CliRunner()
    result = runner.invoke(run, ['version'])
    assert result.exit_code == 0
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


# This is parametrized via `pytest_generate_tests` above
def test_cli_option_dependencies(args, error_message):
    runner = CliRunner()
    result = runner.invoke(run, args)
    assert result.exit_code == 2
    assert error_message in result.output


@pytest.mark.timeout(65)
def test_cli_full_init(cli_args):
    child = spawn_raiden(cli_args)
    try:
        # expect the default mode
        expect_cli_normal_startup(child, EXPECTED_DEFAULT_ENVIRONMENT_VALUE)
    except pexpect.TIMEOUT as e:
        print('Timed out at', e)
    finally:
        child.close()


@pytest.mark.timeout(35)
@pytest.mark.parametrize('changed_args', [{'keystore_path': '.'}])
def test_cli_wrong_keystore_path(cli_args):
    child = spawn_raiden(cli_args)
    try:
        expect_cli_until_acknowledgment(child)
        child.expect('No Ethereum accounts found in the provided keystore directory')
    except pexpect.TIMEOUT as e:
        print('PEXPECT timed out at', e)
    finally:
        child.close()


@pytest.mark.timeout(35)
@pytest.mark.parametrize('removed_args', [['password_file']])
def test_cli_missing_password_file_enter_password(blockchain_provider, cli_args):
    child = spawn_raiden(cli_args)
    try:
        expect_cli_until_account_selection(child)
        child.expect('Enter the password to unlock')
        with open(blockchain_provider['password_file'], 'r') as password_file:
            password = password_file.readline()
            child.sendline(password)
        expect_cli_successful_connected(child, EXPECTED_DEFAULT_ENVIRONMENT_VALUE)
    except pexpect.TIMEOUT as e:
        print('Timed out at', e)
    finally:
        child.close()


@pytest.mark.timeout(65)
@pytest.mark.parametrize('removed_args', [['data_dir']])
def test_cli_missing_data_dir(cli_args):
    child = spawn_raiden(cli_args)
    try:
        expect_cli_normal_startup(child, EXPECTED_DEFAULT_ENVIRONMENT_VALUE)
    except pexpect.TIMEOUT as e:
        print('Timed out at', e)
    finally:
        child.close()


@pytest.mark.timeout(35)
@pytest.mark.parametrize('changed_args', [{'eth_rpc_endpoint': 'http://8.8.8.8:2020'}])
def test_cli_wrong_rpc_endpoint(cli_args):
    child = spawn_raiden(cli_args)
    try:
        expect_cli_until_account_selection(child)
        child.expect('Could not contact the ethereum node through JSON-RPC')
    except pexpect.TIMEOUT as e:
        print('Timed out at', e)
    finally:
        child.close()


@pytest.mark.timeout(35)
@pytest.mark.parametrize('changed_args', [{'network_id': '42'}])
def test_cli_wrong_network_id_try_kovan(cli_args):
    child = spawn_raiden(cli_args)
    try:
        expect_cli_until_account_selection(child)
        child.expect(
            "The chosen ethereum network 'kovan' differs from the ethereum "
            "client 'smoketest'",
        )
    except pexpect.TIMEOUT as e:
        print('Timed out at', e)
    finally:
        child.close()


@pytest.mark.timeout(35)
@pytest.mark.parametrize('changed_args', [{
    'tokennetwork_registry_contract_address': '0xdfD10vAe9CCl5EBf11bc6309A0645eFe9f979584',
}])
def test_cli_malformed_registry_address(cli_args):
    child = spawn_raiden(cli_args)
    try:
        child.expect(
            'Error: Invalid value for "--tokennetwork-registry-contract-address"'
            ': Address must be EIP55 checksummed',
        )
    except pexpect.TIMEOUT as e:
        print('Timed out at', e)
    finally:
        child.close()


@pytest.mark.timeout(35)
@pytest.mark.parametrize('changed_args', [{
    'tokennetwork_registry_contract_address': to_checksum_address(
        '0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359',
    ),
}])
def test_cli_registry_address_without_deployed_contract(cli_args):
    child = spawn_raiden(cli_args)
    try:
        expect_cli_until_account_selection(child)
        child.expect('contract does not contain code')
    except pexpect.TIMEOUT as e:
        print('Timed out at', e)
    finally:
        child.close()


@pytest.mark.timeout(65)
@pytest.mark.parametrize('changed_args', [{
    'environment_type': Environment.DEVELOPMENT.value,
}])
def test_cli_change_environment_type(cli_args):
    child = spawn_raiden(cli_args)
    try:
        # expect the provided mode
        expect_cli_normal_startup(child, Environment.DEVELOPMENT.value)
    except pexpect.TIMEOUT as e:
        print('Timed out at', e)
    finally:
        child.close()
