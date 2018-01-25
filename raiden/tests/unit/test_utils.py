import hashlib
import pytest

from raiden.utils import crypto

def test_privtopub():
    privkey = hashlib.sha256(b'secret').hexdigest()
    pubkey = 'a02b9d5fdd1307c2ee4652ba54d492d1fd11a7d1bb3f3a44c4a05e79f19de933924aa2580069952b0140d88de21c367ee4af7c4a906e1498f20ab8f62e4c2921'

    assert pubkey == crypto.privtopub(privkey).hex()