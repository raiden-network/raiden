#!/usr/bin/env python
# -*- coding: utf-8
import json
from ethereum import tester
from raiden.blockchain.abi import get_contract_path

from ethereum import slogging
slogging.configure(":INFO")

log = slogging.getLogger(__name__)

TARGETS = dict(
    registry='Registry.sol',
    discovery='EndpointRegistry.sol',
    token='HumanStandardToken.sol',
)


def deploy_all():
    state = tester.state()
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
    # avoid boost::filesystem::status: File name too long:"HumanStandardToken:66548b...
    [libraries.pop(c) for c in "HumanStandardToken StandardToken".split()]
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
    print json.dumps(dump, indent=2)
    print '--registry_contract_adddress {Registry} --discovery_contract_address {EndpointRegistry}'.format(**deployed)


def deploy_with_dependencies(contract_name, state, libraries=dict()):
    dependencies = find_dependencies(
        get_contract_path(contract_name))
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
                                    )
        libraries[dependency.split('.')[0]] = deployed.address.encode('hex')
        state.mine()
    contract = state.abi_contract(None,
                                  path=get_contract_path(contract_name),
                                  language='solidity',
                                  libraries=libraries
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


if __name__ == '__main__':
    deploy_all()
