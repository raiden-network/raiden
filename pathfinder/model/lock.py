from eth_utils import keccak


class Lock:
    def __init__(self, amount_locked: int, expiration: int, hashlock: bytes):
        self.amount_locked = amount_locked
        self.expiration = expiration
        self.hashlock = hashlock

    def pack(self) -> bytes:
        result = bytearray(72)
        result[0:8] = self.expiration.to_bytes(8, byteorder='big')
        result[8:40] = self.amount_locked.to_bytes(32, byteorder='big')
        result[40:72] = self.hashlock

        return bytes(result)

    def compute_hash(self) -> bytes:
        return keccak(self.pack())
