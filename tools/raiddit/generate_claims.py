from pathlib import Path
from typing import List

import click

from raiden.tests.utils.factories import make_address, make_signer
from raiden.utils.claim import create_hub_jsonl
from raiden.utils.cli import ADDRESS_TYPE, NetworkChoiceType
from raiden.utils.typing import Address, Optional, TokenNetworkAddress
from raiden_contracts.utils.type_aliases import ChainID


@click.group(name="generate")
def generate() -> None:
    pass


@generate.command()
@click.option("--token-network-address", required=True, type=ADDRESS_TYPE)
@click.option(
    "--chain-id",
    default="goerli",
    type=NetworkChoiceType(["mainnet", "ropsten", "rinkeby", "goerli", "kovan", "<CHAIN_ID>"]),
)
@click.option("-h", "--hub-address", type=ADDRESS_TYPE)
@click.option(
    "-u", "--users", default=10, type=int, help="How many users claims should be generated for"
)
@click.option("-o", "--output-file", default=Path("./claims.jsonl"), type=click.Path())
@click.option("--address", "addresses", type=ADDRESS_TYPE, multiple=True)
def hub(
    token_network_address: TokenNetworkAddress,
    chain_id: ChainID,
    hub_address: Optional[Address],
    users: int,
    output_file: Path,
    addresses: List[Address],
) -> None:
    signer = make_signer()
    if hub_address is None:
        hub_address = make_address()

    addresses = list(addresses)
    addresses.extend(make_address() for _ in range(users - len(addresses)))

    if not isinstance(output_file, Path):
        output_file = Path(output_file)  # type: ignore
    create_hub_jsonl(signer, token_network_address, chain_id, hub_address, addresses, output_file)


if __name__ == "__main__":
    generate()
