import os
import sys
from copy import copy

import pexpect
import pytest

from raiden.settings import RED_EYES_CONTRACT_VERSION
from raiden.tests.utils.smoketest import setup_raiden, setup_testchain


@pytest.fixture(scope='session')
def testchain_provider():
    testchain = setup_testchain(print_step=lambda x: None)

    yield testchain

    for geth_process in testchain['processes_list']:
        geth_process.kill()


@pytest.fixture(scope='module')
def cli_tests_contracts_version():
    return RED_EYES_CONTRACT_VERSION


@pytest.fixture(scope='module')
def raiden_testchain(testchain_provider, cli_tests_contracts_version):
    import time
    start_time = time.monotonic()

    result = setup_raiden(
        transport='matrix',
        matrix_server='auto',
        print_step=lambda x: None,
        contracts_version=cli_tests_contracts_version,
        testchain_setup=testchain_provider,
    )
    args = result['args']
    # The setup of the testchain returns a TextIOWrapper but
    # for the tests we need a filename
    args['password_file'] = args['password_file'].name
    print('setup_raiden took', time.monotonic() - start_time)
    return args


@pytest.fixture()
def removed_args():
    return None


@pytest.fixture()
def changed_args():
    return None


@pytest.fixture()
def cli_args(raiden_testchain, removed_args, changed_args):
    initial_args = raiden_testchain.copy()

    if removed_args is not None:
        for arg in removed_args:
            if arg in initial_args:
                del initial_args[arg]

    if changed_args is not None:
        for k, v in changed_args.items():
            initial_args[k] = v

    args = [
        '--no-sync-check',
        '--tokennetwork-registry-contract-address',
        initial_args['tokennetwork_registry_contract_address'],
        '--secret-registry-contract-address',
        initial_args['secret_registry_contract_address'],
        '--endpoint-registry-contract-address',
        initial_args['endpoint_registry_contract_address'],
    ]

    for arg_name, arg_value in initial_args.items():
        if arg_name == 'sync_check':
            # Special case
            continue
        arg_name_cli = '--' + arg_name.replace('_', '-')
        if arg_name_cli not in args:
            args.append(arg_name_cli)
            if arg_value is not None:
                args.append(arg_value)

    return args


@pytest.fixture
def raiden_spawner(tmp_path):
    def spawn_raiden(args):
        # Remove any possibly defined `RAIDEN_*` environment variables from outer scope
        new_env = {k: copy(v) for k, v in os.environ.items() if not k.startswith('RAIDEN')}
        new_env['HOME'] = str(tmp_path)

        return pexpect.spawn(
            sys.executable, ['-m', 'raiden'] + args,
            logfile=sys.stdout,
            encoding='utf-8',
            env=new_env,
        )
    return spawn_raiden
