import pytest

from raiden.settings import DEFAULT_LIMITS_CONTRACT_VERSION
from raiden.tests.utils.smoketest import setup_testchain_and_raiden


def append_arg_if_existing(argname, initial_args, new_args):
    cliname = '--' + argname.replace('_', '-')
    if argname in initial_args:
        new_args.extend([cliname, initial_args[argname]])


@pytest.fixture(scope='session')
def blockchain_provider():
    result = setup_testchain_and_raiden(
        transport='matrix',
        matrix_server='auto',
        print_step=lambda x: None,
        # cli tests should work with production contracts
        contracts_version=DEFAULT_LIMITS_CONTRACT_VERSION,
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

    append_arg_if_existing('keystore_path', initial_args, args)
    append_arg_if_existing('password_file', initial_args, args)
    append_arg_if_existing('datadir', initial_args, args)
    append_arg_if_existing('network_id', initial_args, args)
    append_arg_if_existing('eth_rpc_endpoint', initial_args, args)
    append_arg_if_existing('environment_type', initial_args, args)

    return args
