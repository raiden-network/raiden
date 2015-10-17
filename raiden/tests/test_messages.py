from raiden.messages import Ping, Ack, deserialize, SignatureMissingError
from raiden.utils import privtoaddr, isaddress, pex
import pytest


def test_signature():
    privkey = 'x' * 32
    address = privtoaddr(privkey)
    p = Ping(nonce=0)
    with pytest.raises(SignatureMissingError):
        p.sender
    p.sign(privkey)
    assert p.sender == address
