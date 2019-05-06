from hexbytes import HexBytes

from raiden.tests.utils.factories import make_block_hash
from raiden.utils.typing import Any, Dict, Tuple


class FakeEth:
    def __init__(self, block_to_blockhash: Dict[int, Any]):
        self.block_to_blockhash = block_to_blockhash

    def getBlock(self, number: int) -> Dict[str, Any]:
        block_hash = self.block_to_blockhash[number]
        return {"hash": block_hash}


class FakeWeb3:
    def __init__(self, block_to_blockhash: Dict[int, Any]):
        self.eth = FakeEth(block_to_blockhash)


def create_fake_web3_for_block_hash(number_of_blocks: int = 0) -> Tuple[FakeWeb3, Dict[int, Any]]:
    block_to_blockhash = {}
    for block in range(0, number_of_blocks):
        block_to_blockhash[block] = HexBytes(make_block_hash())

    fake_web3 = FakeWeb3(block_to_blockhash)

    return fake_web3, block_to_blockhash
