from abc import ABC, abstractmethod
from typing import Callable

from eth_keys import keys
from eth_keys.exceptions import BadSignature, ValidationError
from eth_utils import keccak

from raiden.exceptions import InvalidSignature
from raiden.utils.formatting import to_hex_address
from raiden.utils.typing import Address, AddressHex, Signature


def eth_sign_sha3(data: bytes) -> bytes:
    """
    eth_sign/recover compatible hasher
    Prefixes data with "\x19Ethereum Signed Message:\n<len(data)>"
    """
    prefix = b"\x19Ethereum Signed Message:\n"
    if not data.startswith(prefix):
        data = prefix + b"%d%s" % (len(data), data)
    return keccak(data)


def recover(
    data: bytes, signature: Signature, hasher: Callable[[bytes], bytes] = eth_sign_sha3
) -> Address:
    """ eth_recover address from data hash and signature """
    _hash = hasher(data)

    # ecdsa_recover accepts only standard [0,1] v's so we add support also for [27,28] here
    # anything else will raise BadSignature
    if signature[-1] >= 27:  # support (0,1,27,28) v values
        signature = Signature(signature[:-1] + bytes([signature[-1] - 27]))

    try:
        sig = keys.Signature(signature_bytes=signature)
        public_key = keys.ecdsa_recover(message_hash=_hash, signature=sig)
    except (BadSignature, ValidationError) as e:
        raise InvalidSignature() from e
    return public_key.to_canonical_address()


class Signer(ABC):
    """ ABC for Signer interface """

    # attribute or cached property which represents the address of the account of this Signer
    address: Address

    @abstractmethod
    def sign(self, data: bytes, v: int = 27) -> Signature:
        """ Sign data hash (as of EIP191) with this Signer's account """
        pass

    # TODO: signTransaction (replace privkey on JSONRPCClient)
    # issue: https://github.com/raiden-network/raiden/issues/3390
    # @abstractmethod
    # def signTransaction(self, transaction: dict) -> bytes:
    #     """ Allows Signers to sign transactions with account """
    #     pass

    # TODO: signTypedData (one can dream)
    # @abstractmethod
    # def signTypedData(self, data: dict) -> bytes:
    #     """ Allows Signers to sign typed/structured data from EIP-712 with account """
    #     pass

    @property
    def address_hex(self) -> AddressHex:
        return to_hex_address(self.address)

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} for {self.address_hex}>"


class LocalSigner(Signer):
    """ Concrete Signer implementation using a local private key """

    private_key: keys.PrivateKey

    def __init__(self, private_key: bytes) -> None:
        self.private_key = keys.PrivateKey(private_key)
        self.address = self.private_key.public_key.to_canonical_address()

    def sign(self, data: bytes, v: int = 27) -> Signature:
        """ Sign data hash with local private key """
        assert v in (0, 27), "Raiden is only signing messages with v in (0, 27)"
        _hash = eth_sign_sha3(data)
        signature = self.private_key.sign_msg_hash(message_hash=_hash)
        sig_bytes = signature.to_bytes()
        # adjust last byte to v
        return sig_bytes[:-1] + bytes([sig_bytes[-1] + v])
