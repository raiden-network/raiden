from enum import Enum

from eth_utils import to_checksum_address

from raiden.exceptions import MintFailed, RaidenError
from raiden.network.rpc.client import JSONRPCClient
from raiden.network.rpc.smartcontract_proxy import ContractProxy
from raiden.network.rpc.transactions import check_transaction_threw
from raiden.utils.typing import Any, List, TokenAddress, TransactionHash


class MintingMethod(Enum):
    INCREASE_SUPPLY = "increaseSupply"
    MINT = "mint"
    MINT_FOR = "mintFor"


_MINT_ABI = [
    dict(
        name="increaseSupply",
        type="function",
        constant=False,
        payable=False,
        stateMutability="nonPayable",
        inputs=[dict(name="value", type="uint256"), dict(name="to", type="address")],
        outputs=[],
    ),
    dict(
        name="mint",
        type="function",
        constant=False,
        payable=False,
        stateMutability="nonPayable",
        inputs=[dict(name="to", type="address"), dict(name="value", type="uint256")],
        outputs=[],
    ),
    dict(
        name="mintFor",
        type="function",
        constant=False,
        payable=False,
        stateMutability="nonPayable",
        inputs=[dict(name="num", type="uint256"), dict(name="target", type="address")],
        outputs=[],
    ),
]


def token_minting_proxy(client: JSONRPCClient, address: TokenAddress) -> ContractProxy:
    return client.new_contract_proxy(
        contract_interface=_MINT_ABI, contract_address=to_checksum_address(address)
    )


def call_minting_method(
    client: JSONRPCClient, proxy: ContractProxy, contract_method: MintingMethod, args: List[Any]
) -> TransactionHash:
    """ Try to mint tokens by calling `contract_method` on `proxy`.

    Raises:
        MintFailed if anything goes wrong.
    """
    method = contract_method.value

    gas_limit = proxy.estimate_gas("latest", method, *args)
    if gas_limit is None:
        raise MintFailed(
            f"Gas estimation failed. Make sure the token has a "
            f"method named {method} with the expected signature."
        )

    try:
        tx_hash = proxy.transact(method, gas_limit, *args)
    except (RaidenError, ValueError) as e:
        # Re-raise TransactionAlreadyPending etc. as MintFailed.
        # Since the token minting api is not standardized, we also catch ValueErrors
        # that might fall through ContractProxy.transact()'s exception handling.
        raise MintFailed(str(e))

    client.poll(tx_hash)
    if check_transaction_threw(client, tx_hash):
        raise MintFailed(f"Call to contract method {method}: Transaction failed.")

    return tx_hash
