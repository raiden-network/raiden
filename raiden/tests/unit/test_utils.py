import gevent
import pytest
import requests
import responses
from eth_keys.exceptions import BadSignature, ValidationError
from eth_utils import decode_hex, keccak, to_canonical_address

from raiden.api.v1.encoding import CapabilitiesSchema
from raiden.exceptions import InvalidSignature
from raiden.network.utils import get_average_http_response_time
from raiden.settings import CapabilitiesConfig
from raiden.transfer.utils.secret import decrypt_secret, encrypt_secret
from raiden.utils.capabilities import capconfig_to_dict, capdict_to_config
from raiden.utils.keys import privatekey_to_publickey
from raiden.utils.signer import LocalSigner, Signer, recover
from raiden.utils.typing import UserID


def test_privatekey_to_publickey():
    privkey = keccak(b"secret")
    pubkey = (
        "c283b0507c4ec6903a49fac84a5aead951f3c38b2c72b69da8a70a5bac91e9c"
        "705f70c7554b26e82b90d2d1bbbaf711b10c6c8b807077f4070200a8fb4c6b771"
    )

    assert pubkey == privatekey_to_publickey(privkey).hex()


def test_signer_sign():
    privkey = keccak(b"secret")  # 0x38e959391dD8598aE80d5d6D114a7822A09d313A
    message = b"message"
    # generated with Metamask's web3.personal.sign
    signature = decode_hex(
        "0x1eff8317c59ab169037f5063a5129bb1bab0299fef0b5621d866b07be59e2c0a"
        "6a404e88d3360fb58bd13daf577807c2cf9b6b26d80fc929c52e952769a460981c"
    )

    signer: Signer = LocalSigner(privkey)

    assert signer.sign(message) == signature


def test_encrypt_secret():
    privkey = keccak(b"secret")
    message = b"message"
    signer: Signer = LocalSigner(privkey)
    signature = signer.sign(message)

    encrypted_secret = encrypt_secret(
        message, {"user_id": UserID(message.decode()), "displayname": signature.hex()}, 0, 0
    )

    decrypted_message, amount, payment_id = decrypt_secret(encrypted_secret, privkey)
    assert decrypted_message == message
    assert amount == 0
    assert payment_id == 0


def test_recover():
    account = to_canonical_address("0x38e959391dD8598aE80d5d6D114a7822A09d313A")
    message = b"message"
    # generated with Metamask's web3.personal.sign
    signature = decode_hex(
        "0x1eff8317c59ab169037f5063a5129bb1bab0299fef0b5621d866b07be59e2c0a"
        "6a404e88d3360fb58bd13daf577807c2cf9b6b26d80fc929c52e952769a460981c"
    )

    assert recover(data=message, signature=signature) == account


@pytest.mark.parametrize(
    ("signature", "nested_exception"),
    [
        pytest.param(b"\x00" * 65, BadSignature, id="BadSignature"),
        pytest.param(b"bla", ValidationError, id="ValidationError"),
    ],
)
def test_recover_exception(signature, nested_exception):
    with pytest.raises(InvalidSignature) as exc_info:
        recover(b"bla", signature)
    assert isinstance(exc_info.value.__context__, nested_exception)


def test_get_http_rtt_happy(requests_responses):
    """Ensure get_http_rtt returns the average RTT over the number of samples."""
    delay = iter([0.05, 0.05, 0.2])

    def response(_):
        gevent.sleep(next(delay))
        return 200, {}, ""

    requests_responses.add_callback(responses.GET, "http://url", callback=response)

    result = get_average_http_response_time(url="http://url", method="get", samples=3)
    assert 0.1 <= result[1] < 0.11  # exact answer is 0.1, but we have some overhead


def test_get_http_rtt_ignore_failing(requests_responses):
    """Ensure get_http_rtt ignores failing servers."""

    # RequestException (e.g. DNS not resolvable, server not reachable)
    requests_responses.add(responses.GET, "http://url1", body=requests.RequestException())
    assert get_average_http_response_time(url="http://url1", method="get") is None

    # Server misconfigured
    requests_responses.add(responses.GET, "http://url2", status=404)
    assert get_average_http_response_time(url="http://url2", method="get") is None

    # Internal server error
    requests_responses.add(responses.GET, "http://url3", status=500)
    assert get_average_http_response_time(url="http://url3", method="get") is None


def test_deserialize_capabilities():
    capabilities_schema = CapabilitiesSchema()
    base_url = "mxc://raiden.network/cap"
    capstring = f"{base_url}?foo=1&toad=1&bar=max&form=1&agar=1&nottrue=0&l=one&l=2"
    parsed = capabilities_schema.load({"capabilities": capstring})["capabilities"]
    assert parsed.get("foo") is True
    assert parsed.get("toad") is True
    assert parsed.get("bar") == "max"
    assert parsed.get("agar") is True
    assert parsed.get("nottrue") is False
    assert parsed.get("l") == ["one", "2"]
    assert not parsed.get("nothing")

    assert capabilities_schema.dump({"capabilities": parsed})["capabilities"] == f"{capstring}"

    parsed["false"] = False

    # Explicit new value changes the serialization format
    assert (
        capabilities_schema.dump({"capabilities": parsed})["capabilities"] != f"mxc://{capstring}"
    )

    assert capabilities_schema.load({"capabilities": ""})["capabilities"] == {}

    assert capabilities_schema.load({})["capabilities"] == "mxc://"


def test_capconfig_to_dict():
    # test method supports adding unknown keys
    config = CapabilitiesConfig()
    config.foo = True
    as_dict = capconfig_to_dict(config)

    assert as_dict.get("foo") is True
    assert as_dict.get("bar") is None

    assert capdict_to_config(as_dict) == config
    as_dict["bar"] = True
    assert capdict_to_config(as_dict).bar is True  # pylint: disable=no-member
