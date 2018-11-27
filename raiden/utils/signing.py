from coincurve import PrivateKey, PublicKey
from eth_utils import decode_hex, keccak, remove_0x_prefix, to_bytes
from web3.utils.abi import map_abi_data
from web3.utils.encoding import hex_encode_abi_type
from web3.utils.normalizers import abi_address_to_hex

from raiden.exceptions import InvalidSignature
from raiden.utils.typing import Address, Callable, Optional, Union

sha3 = keccak
Hasher = Optional[Callable[[bytes], bytes]]


def eth_sign_sha3(data: bytes) -> bytes:
    """
    eth_sign/recover compatible hasher
    Prefixes data with "\x19Ethereum Signed Message:\n<len(data)>"
    """
    prefix = b'\x19Ethereum Signed Message:\n'
    if not data.startswith(prefix):
        data = prefix + b'%d%s' % (len(data), data)
    return sha3(data)


def public_key_to_address(public_key: Union[PublicKey, bytes]) -> Address:
    """ Converts a public key to an Ethereum address. """
    if isinstance(public_key, PublicKey):
        public_key = public_key.format(compressed=False)
    assert isinstance(public_key, bytes)
    return sha3(public_key[1:])[-20:]


def address_from_signature(data: bytes, signature: bytes, hasher: Hasher = sha3) -> Address:
    """Convert an EC signature into an ethereum address"""
    if not isinstance(signature, bytes) or len(signature) != 65:
        raise InvalidSignature('Invalid signature, must be 65 bytes')
    v = signature[-1]
    # Support Ethereum's EC v value of 27,28 but also 0,1 to be in
    # sync with the values accepted by the contracts:
    # https://github.com/raiden-network/raiden-contracts/blob/aea36ce403605670edc23fe0d14cf422e2b8e69b/raiden_contracts/contracts/lib/ECVerify.sol#L27
    if v in (27, 28):
        signature = signature[:-1] + bytes([signature[-1] - 27])
    elif v not in (0, 1):
        raise InvalidSignature(f'Invalid signature. v value of {v} is illegal.')

    try:
        signer_pubkey = PublicKey.from_signature_and_message(signature, data, hasher=hasher)
        return public_key_to_address(signer_pubkey)
    except Exception as e:  # pylint: disable=broad-except
        # coincurve raises bare exception on verify error
        raise InvalidSignature('Invalid signature') from e


def eth_recover(data: bytes, signature: bytes, hasher: Hasher = eth_sign_sha3) -> Address:
    """ Recover an address (hex encoded) from an eth_sign data and signature """
    return address_from_signature(data=data, signature=signature, hasher=hasher)


def sign(
        privkey: Union[str, bytes, PrivateKey],
        data: bytes,
        v: int = 27,
        hasher: Hasher = sha3,
) -> bytes:
    if isinstance(privkey, str):
        privkey = to_bytes(hexstr=privkey)
    if isinstance(privkey, bytes):
        privkey = PrivateKey(privkey)
    sig = privkey.sign_recoverable(data, hasher=hasher)
    assert v in (0, 27), 'Raiden is only signing messages with v in (0, 27)'
    return sig[:-1] + bytes([sig[-1] + v])


def eth_sign(
        privkey: Union[str, bytes, PrivateKey],
        data: bytes,
        v: int = 27,
        hasher: Hasher = eth_sign_sha3,
) -> bytes:
    return sign(privkey, data, v=v, hasher=hasher)


def pack_data(abi_types, values) -> bytes:
    """Normalize data and pack them into a byte array"""
    if len(abi_types) != len(values):
        raise ValueError(
            "Length mismatch between provided abi types and values.  Got "
            "{0} types and {1} values.".format(len(abi_types), len(values)),
        )

    normalized_values = map_abi_data([abi_address_to_hex], abi_types, values)

    return decode_hex(''.join(
        remove_0x_prefix(hex_encode_abi_type(abi_type, value))
        for abi_type, value
        in zip(abi_types, normalized_values)
    ))
