from eth_utils import decode_hex, keccak, remove_0x_prefix
from web3.utils.abi import map_abi_data
from web3.utils.encoding import hex_encode_abi_type
from web3.utils.normalizers import abi_address_to_hex

sha3 = keccak


def pack_data(abi_types, values) -> bytes:
    """Normalize data and pack them into a byte array"""
    if len(abi_types) != len(values):
        raise ValueError(
            "Length mismatch between provided abi types and values.  Got "
            "{0} types and {1} values.".format(len(abi_types), len(values))
        )

    normalized_values = map_abi_data([abi_address_to_hex], abi_types, values)

    return decode_hex(
        "".join(
            remove_0x_prefix(hex_encode_abi_type(abi_type, value))
            for abi_type, value in zip(abi_types, normalized_values)
        )
    )
