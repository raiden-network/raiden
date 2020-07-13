import json
from pathlib import Path
from typing import List, Tuple

import click

from raiden.claim import Claim
from raiden.tests.utils.factories import make_address, make_signer
from raiden.utils.cli import ADDRESS_TYPE
from raiden.utils.formatting import to_checksum_address
from raiden.utils.signer import Signer
from raiden.utils.typing import Address, Optional, TokenNetworkAddress
from raiden_contracts.utils.type_aliases import ChainID, TokenAmount

DEFAULT_TOKEN_AMOUNT = TokenAmount(100)


@click.group(name="generate")
def generate():
    pass


@generate.command()
@click.option("--token-network-address", required=True, type=ADDRESS_TYPE)
@click.option("--chain-id", default=5, type=ChainID)
@click.option("-h", "--hub-address", type=ADDRESS_TYPE)
@click.option(
    "-u", "--users", default=10, type=int, help="How many users claims should be generated for",
)
@click.option("-o", "--output-file", default=Path("./claims.json"), type=click.Path())
@click.argument("addresses", required=True, type=ADDRESS_TYPE, nargs=-1)
def hub(
    token_network_address: TokenNetworkAddress,
    chain_id: ChainID,
    hub_address: Optional[Address],
    users: int,
    output_file: Path,
    addresses: List[Address],
):
    signer = make_signer()
    if hub_address is None:
        hub_address = make_address()

    create_hub_json(
        signer, token_network_address, chain_id, hub_address, users, addresses, output_file
    )


def create_hub_json(
    operator_signer: Signer,
    token_network_address: TokenNetworkAddress,
    chain_id: ChainID,
    hub_address: Address,
    num_users: int,
    addresses: List[Address],
    output_file: Path,
) -> None:
    claims = create_hub_claims(
        operator_signer, token_network_address, chain_id, hub_address, num_users, addresses
    )

    claims_data = dict(
        operator=to_checksum_address(operator_signer.address),
        hub=to_checksum_address(hub_address),
        claims=[claim.serialize() for claim in claims],
    )
    output_file.write_text(json.dumps(claims_data))


def generate_claims(
    operator_signer: Signer,
    token_network_address: TokenNetworkAddress,
    chain_id: ChainID,
    channels: List[Tuple[Address, Address, TokenAmount]],
) -> List[Claim]:
    claims = []

    for p1, p2, amount in channels:
        claim = Claim(
            chain_id=chain_id,
            token_network_address=token_network_address,
            owner=p1,
            partner=p2,
            total_amount=amount,
        )
        claim.sign(operator_signer)
        claims.append(claim)

    return claims


def create_hub_claims(
    operator_signer: Signer,
    token_network_address: TokenNetworkAddress,
    chain_id: ChainID,
    hub_address: Address,
    num_users: int,
    addresses: List[Address],
) -> List[Claim]:
    addresses.extend(make_address() for _ in range(num_users - len(addresses)))

    channels = []
    for address in addresses:
        channels.append((address, hub_address, DEFAULT_TOKEN_AMOUNT))
        channels.append((hub_address, address, DEFAULT_TOKEN_AMOUNT))

    return generate_claims(operator_signer, token_network_address, chain_id, channels)


if __name__ == "__main__":
    generate()
