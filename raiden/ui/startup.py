import sys
from typing import Any, Dict

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
) -> Dict[str, Any]:
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
