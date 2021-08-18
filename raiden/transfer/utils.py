import json
import random
from random import Random
from typing import TYPE_CHECKING

from ecies import decrypt, encrypt
from eth_hash.auto import keccak
from eth_utils import decode_hex, encode_hex

from raiden.constants import EMPTY_HASH, LOCKSROOT_OF_NO_LOCKS
from raiden.exceptions import InvalidSecret
from raiden.utils.signer import get_public_key
from raiden.utils.typing import (
    AddressMetadata,
    Any,
    BalanceHash,
    EncryptedSecret,
    LockedAmount,
    Locksroot,
    Optional,
    PaymentAmount,
    PaymentID,
    PrivateKey,
    Secret,
    SecretHash,
    Signature,
    TokenAmount,
    Tuple,
    Union,
)

if TYPE_CHECKING:
    # pylint: disable=unused-import
    from raiden.transfer.mediated_transfer.state_change import ReceiveSecretReveal  # noqa: F401
    from raiden.transfer.state_change import ContractReceiveSecretReveal  # noqa: F401


def hash_balance_data(
    transferred_amount: TokenAmount, locked_amount: LockedAmount, locksroot: Locksroot
) -> BalanceHash:
    assert locksroot != b"", "Can't hash empty locksroot"
    assert len(locksroot) == 32, "Locksroot has wrong length"
    if transferred_amount == 0 and locked_amount == 0 and locksroot == LOCKSROOT_OF_NO_LOCKS:
        return BalanceHash(EMPTY_HASH)

    return BalanceHash(
        keccak(
            transferred_amount.to_bytes(32, byteorder="big")
            + locked_amount.to_bytes(32, byteorder="big")
            + locksroot
        )
    )


def pseudo_random_generator_from_json(data: Any) -> Random:
    # JSON serializes a tuple as a list
    pseudo_random_generator = random.Random()
    state = list(data["pseudo_random_generator"])  # copy
    state[1] = tuple(state[1])  # fix type
    pseudo_random_generator.setstate(tuple(state))

    return pseudo_random_generator


def is_valid_secret_reveal(
    state_change: Union["ContractReceiveSecretReveal", "ReceiveSecretReveal"],
    transfer_secrethash: SecretHash,
) -> bool:
    return state_change.secrethash == transfer_secrethash


def encrypt_secret(
    secret: Secret,
    target_metadata: Optional[AddressMetadata],
    amount: PaymentAmount,
    payment_identifier: PaymentID,
) -> Optional[EncryptedSecret]:
    if not target_metadata or not secret:
        return None

    message = target_metadata["user_id"].encode()
    signature = Signature(decode_hex(target_metadata["displayname"]))

    public_key = get_public_key(message, signature)
    encrypted_secret = None
    if public_key:
        to_encrypt = {
            "secret": encode_hex(secret),
            "amount": amount,
            "payment_identifier": payment_identifier,
        }
        encrypted_secret = EncryptedSecret(
            encrypt(public_key.to_hex(), json.dumps(to_encrypt).encode())
        )
    return encrypted_secret


def decrypt_secret(
    encrypted_secret: EncryptedSecret, private_key: PrivateKey
) -> Tuple[Secret, PaymentAmount, PaymentID]:
    try:
        secret_dict = json.loads(decrypt(private_key, encrypted_secret).decode())
    except (ValueError, json.JSONDecodeError):
        raise InvalidSecret
    secret = Secret(decode_hex(secret_dict["secret"]))
    amount = PaymentAmount(secret_dict["amount"])
    payment_id = PaymentID(secret_dict["payment_identifier"])
    return secret, amount, payment_id
