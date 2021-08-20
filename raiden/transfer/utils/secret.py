import json
from copy import deepcopy
from dataclasses import dataclass
from json import JSONDecodeError

from ecies import decrypt, encrypt
from eth_utils import decode_hex
from marshmallow import ValidationError
from marshmallow_dataclass import class_schema

from raiden.exceptions import InvalidSecret, SerializationError
from raiden.storage.serialization.schemas import BaseSchema
from raiden.storage.serialization.serializer import SerializationBase
from raiden.utils.signer import get_public_key
from raiden.utils.typing import (
    AddressMetadata,
    EncryptedSecret,
    Optional,
    PaymentAmount,
    PaymentID,
    PaymentWithFeeAmount,
    PrivateKey,
    Secret,
    Signature,
    Tuple,
    Union,
)


@dataclass(frozen=True)
class _DecryptedSecret:
    secret: Secret
    amount: PaymentAmount
    payment_identifier: PaymentID

    class Meta:
        add_class_types = False


class SecretSerializer(SerializationBase):
    @staticmethod
    def serialize(obj: _DecryptedSecret) -> bytes:
        if not isinstance(obj, _DecryptedSecret):
            raise SerializationError(f"Can only serialize {_DecryptedSecret.__name__} objects")
        try:
            schema = class_schema(_DecryptedSecret, base_schema=BaseSchema)()
            data = schema.dump(obj)
            data = json.dumps(data).encode()
            return data
        except (AttributeError, TypeError, ValidationError, ValueError, JSONDecodeError) as ex:
            raise SerializationError(f"Can't serialize: {obj}") from ex

    @staticmethod
    def deserialize(data: bytes) -> _DecryptedSecret:
        try:
            obj = json.loads(data.decode())
            schema = class_schema(_DecryptedSecret, base_schema=BaseSchema)()
            return schema.load(deepcopy(obj))
        except (ValueError, TypeError, ValidationError, JSONDecodeError) as ex:
            raise SerializationError(f"Can't deserialize: {data!r}") from ex


def encrypt_secret(
    secret: Optional[Secret],
    target_metadata: Optional[AddressMetadata],
    amount: Union[PaymentAmount, PaymentWithFeeAmount],
    payment_identifier: PaymentID,
) -> Optional[EncryptedSecret]:
    if not target_metadata or not secret:
        return None

    message = target_metadata["user_id"].encode()
    signature = Signature(decode_hex(target_metadata["displayname"]))

    public_key = get_public_key(message, signature)
    encrypted_secret = None
    if public_key:
        decrypted_secret = _DecryptedSecret(
            secret=secret, amount=PaymentAmount(amount), payment_identifier=payment_identifier
        )
        encoded_secret_raw = SecretSerializer.serialize(decrypted_secret)
        encrypted_secret = EncryptedSecret(encrypt(public_key.to_hex(), encoded_secret_raw))
    return encrypted_secret


def decrypt_secret(
    encrypted_secret: EncryptedSecret, private_key: PrivateKey
) -> Tuple[Secret, PaymentAmount, PaymentID]:
    try:
        decrypted_secret_raw = decrypt(private_key, encrypted_secret)
        decrypted_secret = SecretSerializer.deserialize(decrypted_secret_raw)
    except SerializationError:
        raise InvalidSecret
    return decrypted_secret.secret, decrypted_secret.amount, decrypted_secret.payment_identifier
