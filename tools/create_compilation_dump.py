#!/usr/bin/env python
# -*- coding: utf-8
import json
from ethereum import tester
from ethereum.utils import remove_0x_head
from raiden.utils import privatekey_to_address, get_contract_path

from ethereum import slogging
slogging.configure(":INFO")

log = slogging.getLogger(__name__)

TARGETS = dict(
    registry='Registry.sol',
    discovery='EndpointRegistry.sol',
    token='HumanStandardToken.sol',
)

DEFAULT_KEY = ('1' * 64).decode('hex')
DEFAULT_ACCOUNT = privatekey_to_address(DEFAULT_KEY)


def deploy_all(token_groups=dict()):
    log.DEV("default key", raw=tester.DEFAULT_KEY, enc=tester.DEFAULT_KEY.encode('hex'))
    log.DEV("default account", raw=tester.DEFAULT_ACCOUNT, enc=tester.DEFAULT_ACCOUNT.encode('hex'))
    tester.DEFAULT_KEY = DEFAULT_KEY
    tester.DEFAULT_ACCOUNT = DEFAULT_ACCOUNT
    tester.keys[0] = DEFAULT_KEY
    tester.accounts[0] = DEFAULT_ACCOUNT
    log.DEV("default key", raw=tester.DEFAULT_KEY, enc=tester.DEFAULT_KEY.encode('hex'))
    log.DEV("default account", raw=tester.DEFAULT_ACCOUNT, enc=tester.DEFAULT_ACCOUNT.encode('hex'))
    state = tester.state(num_accounts=1)
    log.DEV('state', coinbase=state.block.coinbase.encode('hex'), balance=state.block.get_balance(DEFAULT_ACCOUNT))
    tester.gas_limit = 10 * 10 ** 6
    state.block.number = 1158001

    deployed = dict()

    tokens = dict()
    for name, group in token_groups.items():
        token_name, address = create_and_distribute_token(state, group, name)
        tokens[token_name] = address
        deployed[token_name] = address

    deployed.update(
        deploy_with_dependencies(
            TARGETS['token'],
            state
        )
    )
    libraries = deployed.copy()
    deployed.update(
        deploy_with_dependencies(
            TARGETS['registry'],
            state,
            libraries=libraries
        )
    )
    deployed.update(
        deploy_with_dependencies(
            TARGETS['discovery'],
            state
        )
    )

    dump = dict()
    for account in deployed.values():
        dump.update({account: state.block.account_to_dict(account)})
    cleanup(dump)

    blockchain_config = dict(
        raiden_flags='--registry_contract_address {Registry} --discovery_contract_address {EndpointRegistry}'
        .format(**deployed),
        token_groups=tokens,
    )
    blockchain_config['contract_addresses'] = deployed
    return (dump, blockchain_config)


def create_and_distribute_token(state,
                                receivers,
                                name=None,
                                amount_per_receiver=1000):
    proxy = state.abi_contract(
        None,
        path=get_contract_path(TARGETS['token']),
        language='solidity',
        listen=False,
        sender=DEFAULT_KEY,
        constructor_parameters=(
            len(receivers) * amount_per_receiver,
            name,
            2,
            name[:4].upper()
        )
    )
    for receiver in receivers:
        proxy.transfer(receiver, amount_per_receiver)
    state.mine(number_of_blocks=1)
    return (name, proxy.address.encode('hex'))


def deploy_with_dependencies(contract_name, state, libraries=dict()):
    dependencies = find_dependencies(
        get_contract_path(contract_name))

    dependency_names = [d.split('.')[0] for d in dependencies]
    for key in list(libraries.keys()):
        if not key in dependency_names:
            libraries.pop(key)

    log.DEV("in deploy_with_dependencies", contract=contract_name, dependencies=dependencies)
    for dependency in dependencies:
        # 'Contract's are included in 'Registry' and should not be deployed alone
        if 'Contract' in dependency:
            continue

        log.DEV('deploying dependency', name=dependency)
        log.DEV('known libraries', libraries=libraries)
        deployed = state.abi_contract(None,
                                      path=get_contract_path(dependency),
                                      listen=False,
                                      language='solidity',
                                      libraries=libraries,
                                      sender=DEFAULT_KEY,
                                      )
        libraries[dependency.split('.')[0]] = deployed.address.encode('hex')
        state.mine()

    log.DEV('deploying target', name=contract_name)
    log.DEV('known libraries', libraries=libraries)

    contract = state.abi_contract(
        None,
        path=get_contract_path(contract_name),
        language='solidity',
        libraries=libraries,
        sender=DEFAULT_KEY,
    )

    libraries[contract_name.split('.')[0]] = contract.address.encode('hex')
    state.mine()
    return libraries


def find_dependencies(contract_file):
    """Resolve solidity dependencies depth first.
    """
    dependencies = []
    with open(contract_file) as f:
        for line in f.readlines():
            if line.startswith("import"):
                dependency = line.split()[1].split('"')[1]
                dependency = dependency.rsplit('/', 1)[-1]
                if dependency not in dependencies:
                    dependencies.extend(find_dependencies(get_contract_path(dependency)))
                dependencies.append(dependency)
    cleaned = []
    for dependency in dependencies:
        if dependency not in cleaned:
            cleaned.append(dependency)
    return cleaned


def cleanup(dump):
    def strip_hex(val):
        if isinstance(val, basestring):
            return remove_0x_head(val)
        return val

    for account, alloc in dump.items():
        for key, value in alloc.items():
            alloc[key] = strip_hex(value)


if __name__ == '__main__':
    pretty = False
    dump, blockchain_config = deploy_all()
    print json.dumps(dump, indent=2 if pretty else None)
    print json.dumps(blockchain_config, indent=2 if pretty else None)
