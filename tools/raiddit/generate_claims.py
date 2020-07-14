import json
from pathlib import Path
from typing import List, Tuple

import click

from raiden.tests.utils.factories import make_address, make_signer
from raiden.transfer.state import Claim
from raiden.utils.cli import ADDRESS_TYPE
from raiden.utils.formatting import to_checksum_address
from raiden.utils.signer import Signer
from raiden.utils.typing import Address, Dict, Optional, TokenNetworkAddress
from raiden_contracts.utils.type_aliases import ChainID, TokenAmount

DEFAULT_TOKEN_AMOUNT = TokenAmount(100)


@click.group(name="generate")
def generate() -> None:
    pass


@generate.command()
@click.option("--token-network-address", required=True, type=ADDRESS_TYPE)
@click.option("--chain-id", default=5, type=ChainID)
@click.option("-h", "--hub-address", type=ADDRESS_TYPE)
@click.option(
    "-u", "--users", default=10, type=int, help="How many users claims should be generated for"
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
) -> None:
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


def generate_claim(
    operator_signer: Signer,
    token_network_address: TokenNetworkAddress,
    chain_id: ChainID,
    address: Address,
    partner: Address,
    amount: TokenAmount,
) -> Claim:
    claim = Claim(
        chain_id=chain_id,
        token_network_address=token_network_address,
        owner=address,
        partner=partner,
        total_amount=amount,
    )
    claim.sign(operator_signer)
    return claim


def generate_claims(
    operator_signer: Signer,
    token_network_address: TokenNetworkAddress,
    chain_id: ChainID,
    channels: List[Tuple[Address, Address, TokenAmount]],
) -> List[Claim]:
    claims = []

    for p1, p2, amount in channels:
        claim = generate_claim(
            operator_signer=operator_signer,
            chain_id=chain_id,
            token_network_address=token_network_address,
            address=p1,
            partner=p2,
            amount=amount,
        )
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


class ClaimGenerator:
    """ Class for iteratively adding claims, can be used in test fixtures, etc... """

    def __init__(self, operator_signer: Signer, chain_id: ChainID, hub_address: Optional[Address]):
        self.operator_signer = operator_signer
        self.chain_id = chain_id
        self.hub_address = hub_address
        self.tokennetworkaddress_claims: Dict[TokenNetworkAddress, List[Claim]] = dict()

    def add_claim(
        self,
        amount: TokenAmount,
        address: Address,
        partner: Optional[Address],
        token_network_address: TokenNetworkAddress,
    ) -> Claim:
        """ Adds a claim between `address` and `partner` (or hub if `None`).
        Returns the newly generated claim.
        """
        if partner is None:
            partner = self.hub_address
        if partner is None:
            raise ValueError("No partner, and no hub_address, can not generate claim")
        if token_network_address not in self.tokennetworkaddress_claims:
            self.tokennetworkaddress_claims[token_network_address] = list()
        claim = generate_claim(
            operator_signer=self.operator_signer,
            chain_id=self.chain_id,
            address=address,
            partner=partner,
            amount=amount,
            token_network_address=token_network_address,
        )
        self.tokennetworkaddress_claims[token_network_address].append(claim)
        return claim

    def add_2_claims(
        self,
        amounts: Tuple[TokenAmount, TokenAmount],
        address: Address,
        partner: Optional[Address],
        token_network_address: TokenNetworkAddress,
    ) -> List[Claim]:
        """ Adds bi-directional claims for `address` and `partner` (or hub if `None`).
        Returns the newly generated claims.
        """
        if partner is None:
            partner = self.hub_address
        if partner is None:
            raise ValueError("No partner, and no hub_address, can not generate claim")
        claims = [
            self.add_claim(
                address=address,
                partner=partner,
                amount=amounts[0],
                token_network_address=token_network_address,
            ),
            self.add_claim(
                address=partner,
                partner=address,
                amount=amounts[1],
                token_network_address=token_network_address,
            ),
        ]
        return claims

    def claims(self) -> List[Claim]:
        claims = []
        for token_network_address in self.tokennetworkaddress_claims.keys():
            for claim in self.tokennetworkaddress_claims[token_network_address]:
                claims.append(claim)
        return sorted(claims)


if __name__ == "__main__":
    generate()
