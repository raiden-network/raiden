from typing import TYPE_CHECKING

from eth_utils import to_checksum_address

from raiden.utils.typing import TokenAddress

if TYPE_CHECKING:
    # pylint: disable=unused-import
    from raiden.network.rpc.client import JSONRPCClient
    from raiden.network.rpc.smartcontract_proxy import ContractProxy


_MINT_ABI = [
    dict(
        name="mintFor",
        type="function",
        constant=False,
        payable=False,
        stateMutability="nonPayable",
        inputs=[dict(name="num", type="uint256"), dict(name="target", type="address")],
        outputs=[],
    )
]


def token_minting_proxy(client: "JSONRPCClient", address: TokenAddress) -> "ContractProxy":
    return client.new_contract_proxy(
        contract_interface=_MINT_ABI, contract_address=to_checksum_address(address)
    )
