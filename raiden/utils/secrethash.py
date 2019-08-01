from hashlib import sha256

from raiden.utils.typing import Secret, SecretHash


def sha256_secrethash(secret: Secret) -> SecretHash:
    """Compute the secret hash using sha256."""
    return SecretHash(sha256(secret).digest())
