from coincurve import PublicKey
import structlog

from raiden.utils import sha3, publickey_to_address


log = structlog.get_logger(__name__)  # pylint: disable=invalid-name


def recover_publickey(messagedata, signature, hasher=sha3):
    if len(signature) != 65:
        raise ValueError('invalid signature')

    signature = signature[:-1] + chr(signature[-1] - 27).encode()
    publickey = PublicKey.from_signature_and_message(
        signature,
        messagedata,
        hasher=hasher,
    )
    return publickey.format(compressed=False)


def recover_publickey_safe(messagedata, signature, hasher=sha3):
    publickey = None

    try:
        publickey = recover_publickey(messagedata, signature, hasher)
    except ValueError:
        # raised if the signature has the wrong length
        log.error('invalid signature')
    except TypeError as e:
        # raised if the PublicKey instantiation failed
        log.error('invalid key data: {}'.format(e))
    except Exception as e:  # pylint: disable=broad-except
        # secp256k1 is using bare Exception classes: raised if the recovery failed
        log.error('error while recovering pubkey: {}'.format(e))

    return publickey


def recover_address(messagedata, signature, hasher=sha3):
    public_key = recover_publickey_safe(messagedata, signature, hasher)
    if public_key is None:
        return None
    return publickey_to_address(public_key)


def sign(messagedata, private_key, hasher=sha3):
    signature = private_key.sign_recoverable(messagedata, hasher=hasher)
    if len(signature) != 65:
        raise ValueError('invalid signature')

    return signature[:-1] + chr(signature[-1] + 27).encode()
