#!/usr/bin/env python
import gzip
import os

import click
import simplejson
from eth_utils import to_canonical_address, to_hex
from requests.exceptions import ConnectionError
from web3 import HTTPProvider, Web3

from raiden.blockchain.events import fetch_all_events_for_a_deployment
from raiden.network.rpc.client import JSONRPCClient
from raiden.settings import DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS, RAIDEN_CONTRACT_VERSION
from raiden.tests.utils import factories
from raiden.ui.app import rpc_normalized_endpoint
from raiden.ui.checks import check_ethereum_network_id, check_synced
from raiden.ui.cli import ETH_NETWORKID_OPTION, ETH_RPC_CONFIG_OPTION
from raiden.utils.cli import NetworkChoiceType, group, option
from raiden.utils.ethereum_clients import VersionSupport, is_supported_client
from raiden.utils.formatting import to_checksum_address
from raiden.utils.typing import (
    BlockNumber,
    Dict,
    SecretRegistryAddress,
    TokenNetworkRegistryAddress,
)
from raiden_contracts.constants import (
    CONTRACT_SECRET_REGISTRY,
    CONTRACT_TOKEN_NETWORK_REGISTRY,
    EVENT_TOKEN_NETWORK_CREATED,
    ID_TO_CHAINNAME,
    ChannelEvent,
)
from raiden_contracts.contract_manager import (
    ContractManager,
    contracts_precompiled_path,
    get_contracts_deployment_info,
)


def format_event_for_serialization(data: Dict):
    """ Convert the values in-place from `bin` to `str` since JSON does not
    support binary values.
    """

    event = data["event"]
    args = data["args"]

    data["transaction_hash"] = to_hex(data["transaction_hash"])
    data["block_hash"] = to_hex(data["block_hash"])

    if event == EVENT_TOKEN_NETWORK_CREATED:
        args["token_network_address"] = to_checksum_address(args["token_network_address"])
        args["token_address"] = to_checksum_address(args["token_address"])

    elif event == ChannelEvent.OPENED:
        args["participant1"] = to_checksum_address(args["participant1"])
        args["participant2"] = to_checksum_address(args["participant2"])

    elif event == ChannelEvent.DEPOSIT:
        args["participant"] = to_checksum_address(args["participant"])

    elif event == ChannelEvent.WITHDRAW:
        args["participant"] = to_checksum_address(args["participant"])

    elif event == ChannelEvent.BALANCE_PROOF_UPDATED:
        args["closing_participant"] = to_checksum_address(args["closing_participant"])
        args["balance_hash"] = to_hex(args["balance_hash"])

    elif event == ChannelEvent.CLOSED:
        args["closing_participant"] = to_checksum_address(args["closing_participant"])
        args["balance_hash"] = to_hex(args["balance_hash"])

    elif event == ChannelEvent.SETTLED:
        args["participant1_locksroot"] = to_checksum_address(args["participant1_locksroot"])
        args["participant2_locksroot"] = to_checksum_address(args["participant2_locksroot"])

    elif event == ChannelEvent.UNLOCKED:
        args["receiver"] = to_checksum_address(args["receiver"])
        args["sender"] = to_checksum_address(args["sender"])


@group(invoke_without_command=True, context_settings={"max_content_width": 120})
@option(
    "--output-directory",
    help="Specify the folder were the snapshot should be saved",
    required=True,
    type=click.Path(
        exists=False,
        dir_okay=True,
        file_okay=False,
        writable=True,
        resolve_path=True,
        allow_dash=False,
    ),
)
@option(
    ETH_NETWORKID_OPTION,
    help=(
        "Specify the network name/id of the Ethereum network to run Raiden on.\n"
        "Available networks:\n"
        '"mainnet" - network id: 1\n'
        '"ropsten" - network id: 3\n'
        '"rinkeby" - network id: 4\n'
        '"goerli" - network id: 5\n'
        '"kovan" - network id: 42\n'
        '"<NETWORK_ID>": use the given network id directly\n'
    ),
    type=NetworkChoiceType(["mainnet", "ropsten", "rinkeby", "goerli", "kovan", "<NETWORK_ID>"]),
    default="mainnet",
    show_default=True,
)
@option(
    ETH_RPC_CONFIG_OPTION,
    help=(
        '"host:port" address of ethereum JSON-RPC server.\n'
        "Also accepts a protocol prefix (http:// or https://) with optional port"
    ),
    default="http://127.0.0.1:8545",  # geth default jsonrpc port
    type=str,
    show_default=True,
)
@option("--contracts-version", default=RAIDEN_CONTRACT_VERSION, type=str, show_default=True)
def main(output_directory, network_id, eth_rpc_endpoint, contracts_version):
    web3 = Web3(HTTPProvider(rpc_normalized_endpoint(eth_rpc_endpoint)))

    try:
        supported, _, _ = is_supported_client(web3.clientVersion)
        assert supported is VersionSupport.SUPPORTED, "Unsupported eth client"
    except ConnectionError:
        click.secho(
            f"Couldn't connect to the ethereum node, double check it is running "
            f"on {eth_rpc_endpoint}, this option can be changed with "
            f"{ETH_RPC_CONFIG_OPTION}",
            fg="red",
        )
        return

    check_ethereum_network_id(network_id, web3)

    # This script does not send any transactions, the privatekey is generate
    # just because it is a dependency for JSONRPCClient.
    unecessary_privatekey = factories.make_privatekey_bin()
    rpc_client = JSONRPCClient(web3=web3, privkey=unecessary_privatekey)
    check_synced(rpc_client)

    deployment_data = get_contracts_deployment_info(chain_id=network_id, version=contracts_version)

    if not deployment_data:
        raise RuntimeError(
            f"There is no deployment data available for contracts-version {contracts_version}."
        )

    network_name = ID_TO_CHAINNAME.get(network_id)
    if network_name is None:
        raise RuntimeError(f"Network with id {network_id} is not known.")

    contracts = deployment_data["contracts"]
    token_network_registry_deployed_at = BlockNumber(
        contracts[CONTRACT_TOKEN_NETWORK_REGISTRY]["block_number"]
    )
    token_network_registry_address = TokenNetworkRegistryAddress(
        to_canonical_address(contracts[CONTRACT_TOKEN_NETWORK_REGISTRY]["address"])
    )
    secret_registry_address = SecretRegistryAddress(
        to_canonical_address(contracts[CONTRACT_SECRET_REGISTRY]["address"])
    )

    contracts_path = contracts_precompiled_path(contracts_version)
    contract_manager = ContractManager(contracts_path)

    current_block_number = rpc_client.block_number()
    confirmed_block = rpc_client.get_block(
        BlockNumber(current_block_number - DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS)
    )

    all_events_for_a_deployment = fetch_all_events_for_a_deployment(
        contract_manager=contract_manager,
        web3=web3,
        token_network_registry_address=token_network_registry_address,
        secret_registry_address=secret_registry_address,
        start_block=token_network_registry_deployed_at,
        target_block=confirmed_block["number"],
    )

    target_block_formatted = to_hex(confirmed_block["hash"])
    file_path = os.path.join(
        output_directory,
        (
            f"{network_name}-"
            f"{to_checksum_address(token_network_registry_address)}-"
            f"{target_block_formatted}.json.gz"
        ),
    )

    block_data = {
        "gasLimit": confirmed_block["gasLimit"],
        "gasUsed": confirmed_block["gasUsed"],
        "hash": to_hex(confirmed_block["hash"]),
        "number": confirmed_block["number"],
    }
    block_data_formatted = simplejson.dumps(block_data).encode("utf8")

    with gzip.open(file_path, mode="wb") as handler:
        # Format is `jsonlines` (http://jsonlines.org/), this is used because we
        # don't have to keep all the events in memory to start encoding the data.
        for event in all_events_for_a_deployment:
            format_event_for_serialization(event)
            data = simplejson.dumps(event).encode("utf8")
            handler.write(data + b"\n")

        # Write the block details at the end
        handler.write(block_data_formatted + b"\n")


if __name__ == "__main__":
    main()  # pylint: disable=all
