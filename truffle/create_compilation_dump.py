#!/usr/bin/env python
# -*- coding: utf-8
import json
from ethereum import tester
from ethereum.utils import privtoaddr, remove_0x_head
from raiden.blockchain.abi import get_contract_path

from ethereum import slogging
slogging.configure(":INFO")

log = slogging.getLogger(__name__)

TARGETS = dict(
    registry='Registry.sol',
    discovery='EndpointRegistry.sol',
    token='HumanStandardToken.sol',
)

DEFAULT_KEY = ('1' * 64).decode('hex')
DEFAULT_ACCOUNT = privtoaddr(DEFAULT_KEY)


def deploy_all():
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

    with open('state_dump_py.json', 'w') as f:
        json.dump(dump, f, indent=2)
    print json.dumps(deployed, indent=2)
    print '--registry_contract_adddress {Registry} --discovery_contract_address {EndpointRegistry}'.format(**deployed)


def deploy_with_dependencies(contract_name, state, libraries=dict()):
    dependencies = find_dependencies(
        get_contract_path(contract_name))
    [libraries.pop(key) for key in libraries.keys() if not key in
     [d.split('.')[0] for d in dependencies]]
    log.DEV("in deploy_with_dependencies", contract=contract_name, dependencies=dependencies)
    for dependency in dependencies:
        # FIXME: this should not be needed!?
        if 'Contract' in dependency:
            continue

        log.DEV('deploying dependency', name=dependency)
        log.DEV('known libraries', libraries=libraries)
        deployed = state.abi_contract(None,
                                      path=get_contract_path(dependency),
                                      language='solidity',
                                      libraries=libraries,
                                      sender=DEFAULT_KEY,
                                      )
        libraries[dependency.split('.')[0]] = deployed.address.encode('hex')
        state.mine()
    log.DEV('deploying target', name=contract_name)
    log.DEV('known libraries', libraries=libraries)
    contract = state.abi_contract(None,
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
    deploy_all()
