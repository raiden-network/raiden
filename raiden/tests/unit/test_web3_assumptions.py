import json
from typing import Any, Callable, Dict, Tuple

import pytest
import responses
from eth_typing import URI, BlockNumber
from requests import PreparedRequest
from web3 import HTTPProvider, Web3
from web3.eth import Eth
from web3.exceptions import BlockNotFound
from web3.gas_strategies.rpc import rpc_gas_price_strategy

from raiden.network.rpc.client import make_patched_web3_get_block, monkey_patch_web3
from raiden.utils.typing import MYPY_ANNOTATION

_FAKE_BLOCK_DATA = {
    "difficulty": "0x1",
    "extraData": "0x1",
    "gasLimit": "0x1",
    "gasUsed": "0x1",
    "hash": "0x1",
    "logsBloom": "0x1",
    "miner": "0x1111111111111111111111111111111111111111",
    "mixHash": "0x1",
    "nonce": "0x1",
    "number": "0x1",
    "parentHash": "0x1",
    "receiptsRoot": "0x1",
    "sha3Uncles": "0x1",
    "size": "0x1",
    "stateRoot": "0x1",
    "timestamp": "0x1",
    "totalDifficulty": "0x1",
    "transactions": [],
    "transactionsRoot": "0x1",
    "uncles": [],
}


@pytest.fixture
def patched_web3():
    web3 = Web3(HTTPProvider(URI("http://domain/")))
    monkey_patch_web3(web3=web3, gas_price_strategy=rpc_gas_price_strategy)
    original_get_block = Eth.getBlock
    Eth.getBlock = make_patched_web3_get_block(Eth.getBlock)
    yield web3
    Eth.getBlock = original_get_block


def _make_json_rpc_null_response(
    succeed_at: int,
) -> Callable[[PreparedRequest], Tuple[int, Dict[str, Any], str]]:
    """ Generate a callback that returns a ``null`` JSONRPC response until ``succeed_at`` retries
    after which it will return a dummy block.
    """
    request_count = 0

    def make_response(request: PreparedRequest) -> Tuple[int, Dict[str, Any], str]:
        nonlocal request_count
        assert isinstance(request.body, bytes), MYPY_ANNOTATION
        id_ = json.loads(request.body.decode()).get("id", 0)

        result = None
        if request_count == succeed_at:
            result = _FAKE_BLOCK_DATA

        request_count += 1
        return 200, {}, json.dumps({"jsonrpc": "2.0", "id": id_, "result": result})

    return make_response


@pytest.mark.parametrize("succeed_at", [0, 1, 2])
def test_web3_retries_block_not_found(
    patched_web3: Web3, succeed_at: int, requests_responses: responses.RequestsMock
):
    requests_responses.add_callback(
        responses.POST, "http://domain/", callback=_make_json_rpc_null_response(succeed_at)
    )

    result = patched_web3.eth.getBlock(BlockNumber(1))
    assert result["number"] == 1


def test_web3_reraises_block_not_found_after_retries(patched_web3, requests_responses):
    requests_responses.add_callback(
        responses.POST, "http://domain/", callback=_make_json_rpc_null_response(100)
    )

    with pytest.raises(BlockNotFound):
        _ = patched_web3.eth.getBlock(1)
