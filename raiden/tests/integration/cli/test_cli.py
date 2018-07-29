import json
import pytest
import pexpect
import sys
from click.testing import CliRunner
from raiden.ui.cli import run
from eth_utils import to_checksum_address


def test_cli_version():
    runner = CliRunner()
    result = runner.invoke(run, ["version"])
    assert result.exit_code == 0
    result_json = json.loads(result.output)
    result_expected_keys = ["raiden", "python_implementation", "python_version", "system"]
    for expected_key in result_expected_keys:
        assert expected_key in result_json


@pytest.mark.timeout(25)
def test_cli_full_init(cli_args):
    child = pexpect.spawn('raiden', cli_args, logfile=sys.stdout)
    try:
        child.expect('Welcome to Raiden')
        child.expect('The following accounts were found in your machine:')
        child.expect('Select one of them by index to continue: ')
        child.sendline('0')
        child.expect('You are connected')
        child.expect('The Raiden API RPC server is now running')
    except pexpect.TIMEOUT as e:
        print("Timed out at", e)
    finally:
        child.close()


@pytest.mark.timeout(25)
def test_cli_missing_keystore_path(blockchain_provider):
    cli_args = ['--password-file', blockchain_provider['password_file_path'],
                '--datadir', blockchain_provider['datadir_path'],
                '--nat', 'none',
                '--no-sync-check',
                '--eth-rpc-endpoint', blockchain_provider['eth_rpc_endpoint'],
                '--network-id', blockchain_provider['network_id'],
                '--registry-contract-address', blockchain_provider['registry_contract_address'],
                '--discovery-contract-address', blockchain_provider['discovery_contract_address']]
    child = pexpect.spawn('raiden',
                          cli_args,
                          logfile=sys.stdout)
    try:
        child.expect('RuntimeError: No Ethereum accounts found in the user\'s system')
    except pexpect.TIMEOUT as e:
        print("PEXPECT timed out at", e)
    finally:
        child.close()


@pytest.mark.timeout(25)
def test_cli_missing_password_file_enter_password(blockchain_provider):
    cli_args = ['--keystore-path', blockchain_provider['keystore_path'],
                '--datadir', blockchain_provider['datadir_path'],
                '--nat', 'none',
                '--no-sync-check',
                '--eth-rpc-endpoint', blockchain_provider['eth_rpc_endpoint'],
                '--network-id', blockchain_provider['network_id'],
                '--registry-contract-address', blockchain_provider['registry_contract_address'],
                '--discovery-contract-address', blockchain_provider['discovery_contract_address']]
    child = pexpect.spawn('raiden',
                          cli_args,
                          logfile=sys.stdout)
    try:
        child.expect('Welcome to Raiden')
        child.expect('The following accounts were found in your machine:')
        child.expect('Select one of them by index to continue: ')
        child.sendline('0')
        child.expect('Enter the password to unlock')
        with open(blockchain_provider['password_file_path'], 'r') as password_file:
            password = password_file.readline()
            child.sendline(password)
        child.expect('You are connected')
        child.expect('The Raiden API RPC server is now running')
    except pexpect.TIMEOUT as e:
        print("Timed out at", e)
    finally:
        child.close()


@pytest.mark.timeout(25)
def test_cli_missing_data_dir(blockchain_provider):
    cli_args = ['--keystore-path', blockchain_provider['keystore_path'],
                '--password-file', blockchain_provider['password_file_path'],
                '--nat', 'none',
                '--no-sync-check',
                '--eth-rpc-endpoint', blockchain_provider['eth_rpc_endpoint'],
                '--network-id', blockchain_provider['network_id'],
                '--registry-contract-address', blockchain_provider['registry_contract_address'],
                '--discovery-contract-address', blockchain_provider['discovery_contract_address']]
    child = pexpect.spawn('raiden',
                          cli_args,
                          logfile=sys.stdout)
    try:
        child.expect('Welcome to Raiden')
        child.expect('The following accounts were found in your machine:')
        child.expect('Select one of them by index to continue: ')
        child.sendline('0')
        child.expect('You are connected')
        child.expect('The Raiden API RPC server is now running')
    except pexpect.TIMEOUT as e:
        print("Timed out at", e)
    finally:
        child.close()


@pytest.mark.timeout(25)
def test_cli_missing_nat(blockchain_provider):
    cli_args = ['--keystore-path', blockchain_provider['keystore_path'],
                '--password-file', blockchain_provider['password_file_path'],
                '--datadir', blockchain_provider['datadir_path'],
                '--no-sync-check',
                '--eth-rpc-endpoint', blockchain_provider['eth_rpc_endpoint'],
                '--network-id', blockchain_provider['network_id'],
                '--registry-contract-address', blockchain_provider['registry_contract_address'],
                '--discovery-contract-address', blockchain_provider['discovery_contract_address']]
    child = pexpect.spawn('raiden',
                          cli_args,
                          logfile=sys.stdout)
    try:
        child.expect('Welcome to Raiden')
        child.expect('no upnp providers found ')
        child.expect('The following accounts were found in your machine:')
        child.expect('Select one of them by index to continue: ')
        child.sendline('0')
        child.expect('You are connected')
    except pexpect.TIMEOUT as e:
        print("Timed out at", e)
    finally:
        child.close()


@pytest.mark.timeout(25)
def test_cli_wrong_rpc_endpoint(blockchain_provider):
    cli_args = ['--keystore-path', blockchain_provider['keystore_path'],
                '--password-file', blockchain_provider['password_file_path'],
                '--datadir', blockchain_provider['datadir_path'],
                '--nat', 'none',
                '--eth-rpc-endpoint', blockchain_provider['eth_rpc_endpoint'] + '0',
                '--network-id', blockchain_provider['network_id'],
                '--registry-contract-address', blockchain_provider['registry_contract_address'],
                '--discovery-contract-address', blockchain_provider['discovery_contract_address']]
    child = pexpect.spawn('raiden',
                          cli_args,
                          logfile=sys.stdout)
    try:
        child.expect('Welcome to Raiden')
        child.expect('The following accounts were found in your machine:')
        child.expect('Select one of them by index to continue: ')
        child.sendline('0')
        child.expect('Could not contact the ethereum node through JSON-RPC')
    except pexpect.TIMEOUT as e:
        print("Timed out at", e)
    finally:
        child.close()


@pytest.mark.timeout(25)
def test_cli_wrong_network_id_try_mainnet(blockchain_provider):
    cli_args = ['--keystore-path', blockchain_provider['keystore_path'],
                '--password-file', blockchain_provider['password_file_path'],
                '--datadir', blockchain_provider['datadir_path'],
                '--nat', 'none',
                '--no-sync-check',
                '--eth-rpc-endpoint', blockchain_provider['eth_rpc_endpoint'],
                '--network-id', '1',
                '--registry-contract-address', blockchain_provider['registry_contract_address'],
                '--discovery-contract-address', blockchain_provider['discovery_contract_address']]
    child = pexpect.spawn('raiden',
                          cli_args,
                          logfile=sys.stdout)
    try:
        child.expect('Welcome to Raiden')
        child.expect('The following accounts were found in your machine:')
        child.expect('Select one of them by index to continue: ')
        child.sendline('0')
        child.expect("The chosen ethereum network 'mainnet' differs from the ethereum "
                     "client 'smoketest'")
    except pexpect.TIMEOUT as e:
        print('Timed out at', e)
    finally:
        child.close()


@pytest.mark.timeout(25)
def test_cli_malformed_registry_address(blockchain_provider):
    malformed_registry_address = blockchain_provider['registry_contract_address'] + '0'
    cli_args = ['--keystore-path', blockchain_provider['keystore_path'],
                '--password-file', blockchain_provider['password_file_path'],
                '--datadir', blockchain_provider['datadir_path'],
                '--nat', 'none',
                '--no-sync-check',
                '--eth-rpc-endpoint', blockchain_provider['eth_rpc_endpoint'],
                '--network-id', blockchain_provider['network_id'],
                '--registry-contract-address', malformed_registry_address,
                '--discovery-contract-address', blockchain_provider['discovery_contract_address']]
    child = pexpect.spawn('raiden',
                          cli_args,
                          logfile=sys.stdout)
    try:
        child.expect('Error: Invalid value for "--registry-contract-address"'
                     ': Provided addresses must be EIP55 checksummed')
    except pexpect.TIMEOUT as e:
        print("Timed out at", e)
    finally:
        child.close()


@pytest.mark.timeout(25)
def test_cli_swap_registry_address_with_discovery_address(blockchain_provider):
    cli_args = ['--keystore-path', blockchain_provider['keystore_path'],
                '--password-file', blockchain_provider['password_file_path'],
                '--datadir', blockchain_provider['datadir_path'],
                '--nat', 'none',
                '--no-sync-check',
                '--eth-rpc-endpoint', blockchain_provider['eth_rpc_endpoint'],
                '--network-id', blockchain_provider['network_id'],
                '--registry-contract-address', blockchain_provider['discovery_contract_address'],
                '--discovery-contract-address', blockchain_provider['registry_contract_address']]
    child = pexpect.spawn('raiden',
                          cli_args,
                          logfile=sys.stdout)
    try:
        child.expect('Welcome to Raiden')
        child.expect('The following accounts were found in your machine:')
        child.expect('Select one of them by index to continue: ')
        child.sendline('0')
        child.expect('You are connected')
        child.expect('web3.exceptions.BadFunctionCallOutput: Could not decode '
                     'contract function call')
    except pexpect.TIMEOUT as e:
        print("Timed out at", e)
    finally:
        child.close()


@pytest.mark.timeout(25)
def test_cli_registry_address_without_deployed_contract(blockchain_provider):
    cli_args = ['--keystore-path', blockchain_provider['keystore_path'],
                '--password-file', blockchain_provider['password_file_path'],
                '--datadir', blockchain_provider['datadir_path'],
                '--nat', 'none',
                '--no-sync-check',
                '--eth-rpc-endpoint', blockchain_provider['eth_rpc_endpoint'],
                '--network-id', blockchain_provider['network_id'],
                '--registry-contract-address',
                to_checksum_address('0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359'),
                '--discovery-contract-address', blockchain_provider['discovery_contract_address']]
    child = pexpect.spawn('raiden',
                          cli_args,
                          logfile=sys.stdout)
    try:
        child.expect('Welcome to Raiden')
        child.expect('The following accounts were found in your machine:')
        child.expect('Select one of them by index to continue: ')
        child.sendline('0')
        child.expect('You are connected')
        child.expect('raiden.exceptions.AddressWithoutCode')
    except pexpect.TIMEOUT as e:
        print("Timed out at", e)
    finally:
        child.close()


@pytest.mark.timeout(25)
def test_cli_missing_discovery_contract_address(blockchain_provider):
    cli_args = ['--keystore-path', blockchain_provider['keystore_path'],
                '--password-file', blockchain_provider['password_file_path'],
                '--datadir', blockchain_provider['datadir_path'],
                '--nat', 'none',
                '--no-sync-check',
                '--eth-rpc-endpoint', blockchain_provider['eth_rpc_endpoint'],
                '--network-id', blockchain_provider['network_id'],
                '--registry-contract-address', blockchain_provider['registry_contract_address']]
    child = pexpect.spawn('raiden',
                          cli_args,
                          logfile=sys.stdout)
    try:
        child.expect('Welcome to Raiden')
        child.expect('The following accounts were found in your machine:')
        child.expect('Select one of them by index to continue: ')
        child.sendline('0')
        child.expect('You are connected')
        child.expect('raiden.exceptions.AddressWithoutCode')
    except pexpect.TIMEOUT as e:
        print("Timed out at", e)
    finally:
        child.close()


@pytest.mark.timeout(25)
def DISABLE_test_cli_eth_client_communication(blockchain_provider,
                                              deploy_client,
                                              blockchain_backend):
    """
    Test if --eth-client-communication displays dumped serialized communication data.
    This test case will fail after JSONRPCClient was moved from pyethapp to Raiden.

    Original implementation dumped serialized request and response to stdout.
    https://github.com/ethereum/pyethapp/blob/develop/pyethapp/rpc_client.py#L381

    Test case simply waits for a JSON string on stdout after triggering RPC call.

    Currently this functionality does not exist anymore and test times out.
    """
    cli_args = ['--keystore-path', blockchain_provider['keystore_path'],
                '--password-file', blockchain_provider['password_file_path'],
                '--datadir', blockchain_provider['datadir_path'],
                '--nat', 'none',
                '--no-sync-check',
                '--eth-rpc-endpoint', blockchain_provider['eth_rpc_endpoint'],
                '--network-id', blockchain_provider['network_id'],
                '--registry-contract-address', blockchain_provider['registry_contract_address'],
                '--discovery-contract-address', blockchain_provider['discovery_contract_address'],
                '--eth-client-communication']
    child = pexpect.spawn('raiden',
                          cli_args,
                          logfile=sys.stdout)
    try:
        child.expect('Welcome to Raiden')
        child.expect('The following accounts were found in your machine:')
        child.expect('Select one of them by index to continue: ')
        child.sendline('0')
        child.expect('You are connected')
        child.expect('The Raiden API RPC server is now running')

        inexisting_address = b'\x01\x02\x03\x04\x05' * 4
        transaction = {
            'from': to_checksum_address(deploy_client.sender),
            'to': to_checksum_address(inexisting_address),
            'data': b'',
            'value': 0,
        }
        rpc_data = deploy_client.web3.eth.call(transaction)
        assert rpc_data == b''
        child.expect('.*{.*}.*')
    except pexpect.TIMEOUT as e:
        print("Timed out at", e)
    finally:
        child.close()
