import pytest

from raiden.settings import RED_EYES_CONTRACT_VERSION
from raiden.tests.utils.smoketest import setup_testchain_and_raiden


@pytest.fixture(scope='session')
def blockchain_provider():
    result = setup_testchain_and_raiden(
        transport='matrix',
        matrix_server='auto',
        print_step=lambda x: None,
        # cli tests should work with production contracts
        contracts_version=RED_EYES_CONTRACT_VERSION,
    )
    args = result['args']
    # The setup of the testchain returns a TextIOWrapper but
    # for the tests we need a filename
    args['password_file'] = args['password_file'].name
    return args


@pytest.fixture()
def removed_args():
    return None


@pytest.fixture()
def changed_args():
    return None


@pytest.fixture()
def cli_args(blockchain_provider, removed_args, changed_args):
    initial_args = blockchain_provider.copy()

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
