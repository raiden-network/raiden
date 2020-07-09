import json
from pathlib import Path

import click

from raiden.claim import Claim
from raiden.tests.utils.factories import make_address, make_signer
from raiden.utils.cli import ADDRESS_TYPE
from raiden.utils.formatting import to_checksum_address
from raiden.utils.typing import Address, Optional, TokenNetworkAddress
from raiden_contracts.utils.type_aliases import ChainID, TokenAmount

DEFAULT_TOKEN_AMOUNT = TokenAmount(100)


@click.group(name="generate")
def generate():
    pass


@generate.command()
@click.option("--address", help="Own address", required=True, type=ADDRESS_TYPE)
@click.option("--token-network-address", required=True, type=ADDRESS_TYPE)
@click.option("--chain-id", default=5, type=ChainID)
@click.option("-h", "--hub-address", type=ADDRESS_TYPE)
@click.option(
    "-u", "--users", default=10, type=int, help="How many users claims should be generated for",
)
@click.option("-o", "--output-file", default=Path("./claims.json"), type=click.Path())
def hub(
    address: Address,
    token_network_address: TokenNetworkAddress,
    chain_id: ChainID,
    hub_address: Optional[Address],
    users: int,
    output_file: Path,
):
    create_hub(address, token_network_address, chain_id, hub_address, users, output_file)


def create_hub(
    address: Address,
    token_network_address: TokenNetworkAddress,
    chain_id: ChainID,
    hub_address: Optional[Address],
    users: int,
    output_file: Path,
):
    signer = make_signer()
    if hub_address is None:
        hub_address = make_address()

    addresses = [address]
    addresses.extend(make_address() for _ in range(users))
    claims = []

    for address in addresses:
        claim = Claim(
            chain_id=chain_id,
            token_network_address=token_network_address,
            owner=address,
            partner=hub_address,
            total_amount=DEFAULT_TOKEN_AMOUNT,
        )
        claim.sign(signer)
        claims.append(claim.serialize())

        reverse_claim = Claim(
            chain_id=chain_id,
            token_network_address=token_network_address,
            owner=hub_address,
            partner=address,
            total_amount=DEFAULT_TOKEN_AMOUNT,
        )
        reverse_claim.sign(signer)
        claims.append(reverse_claim.serialize())

    claims_data = dict(
        operator=to_checksum_address(signer.address),
        hub=to_checksum_address(hub_address),
        claims=claims,
    )
    output_file.write_text(json.dumps(claims_data))


if __name__ == "__main__":
    generate()
