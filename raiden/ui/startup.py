import sys
from typing import Any, Dict, Tuple

import click

from raiden.constants import Environment
from raiden.settings import DEVELOPMENT_CONTRACT_VERSION, RED_EYES_CONTRACT_VERSION
from raiden_contracts.constants import ID_TO_NETWORKNAME
from raiden_contracts.contract_manager import (
    contracts_precompiled_path,
    get_contracts_deployment_info,
)


def setup_network_id_or_exit(
        config: Dict[str, Any],
        given_network_id: int,
        web3,
) -> Tuple[int, bool]
    """
    Takes the given network id and checks it against the connected network

    If they don't match, exits the program with an error. If they do adds it
    to the configuration and then returns it and whether it is a known network
    """
    node_network_id = int(web3.version.network)  # pylint: disable=no-member
    known_given_network_id = given_network_id in ID_TO_NETWORKNAME
    known_node_network_id = node_network_id in ID_TO_NETWORKNAME

    if node_network_id != given_network_id:
        if known_given_network_id and known_node_network_id:
            click.secho(
                f"The chosen ethereum network '{ID_TO_NETWORKNAME[given_network_id]}' "
                f"differs from the ethereum client '{ID_TO_NETWORKNAME[node_network_id]}'. "
                "Please update your settings.",
                fg='red',
            )
        else:
            click.secho(
                f"The chosen ethereum network id '{given_network_id}' differs "
                f"from the ethereum client '{node_network_id}'. "
                "Please update your settings.",
                fg='red',
            )
        sys.exit(1)

    config['chain_id'] = given_network_id
    return given_network_id, known_node_network_id


def setup_environment(config: Dict[str, Any], environment_type: Environment) -> Environment:
    """Sets the config depending on the environment type"""
    # interpret the provided string argument
    if environment_type == Environment.PRODUCTION:
        # Safe configuration: restrictions for mainnet apply and matrix rooms have to be private
        config['environment_type'] = Environment.PRODUCTION
        config['transport']['matrix']['private_rooms'] = True
    else:
        config['environment_type'] = Environment.DEVELOPMENT

    print(f'Raiden is running in {environment_type.value.lower()} mode')
    return environment_type


def setup_contracts_or_exit(
        config: Dict[str, Any],
        network_id: int,
) -> Tuple[Dict[str, Any], bool]:
    """Sets the contract deployment data depending on the network id and environment type


    If an invalid combination of network id and environment type is provided, exits
    the program with an error
    """
    environment_type = config['environment_type']
    contracts = dict()
    contract_addresses_known = False
    if environment_type == Environment.DEVELOPMENT:
        contracts_version = DEVELOPMENT_CONTRACT_VERSION
    else:
        contracts_version = RED_EYES_CONTRACT_VERSION

    config['contracts_path'] = contracts_precompiled_path(contracts_version)

    if network_id in ID_TO_NETWORKNAME and ID_TO_NETWORKNAME[network_id] != 'smoketest':
        deployment_data = get_contracts_deployment_info(
            chain_id=network_id,
            version=contracts_version,
        )
        not_allowed = (  # for now we only disallow mainnet with test configuration
            network_id == 1 and
            environment_type == Environment.DEVELOPMENT
        )
        if not_allowed:
            click.secho(
                f'The chosen network ({ID_TO_NETWORKNAME[network_id]}) is not a testnet, '
                'but the "development" environment was selected.\n'
                'This is not allowed. Please start again with a safe environment setting '
                '(--environment production).',
                fg='red',
            )
            sys.exit(1)

        contracts = deployment_data['contracts']
        contract_addresses_known = True

    return contracts, contract_addresses_known
