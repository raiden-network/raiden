from eth_utils import decode_hex, to_canonical_address

from raiden.utils import privatekey_to_publickey, sha3
from raiden.utils.signer import LocalSigner, Signer, recover


def test_privatekey_to_publickey():
    privkey = sha3(b'secret')
    pubkey = ('c283b0507c4ec6903a49fac84a5aead951f3c38b2c72b69da8a70a5bac91e9c'
              '705f70c7554b26e82b90d2d1bbbaf711b10c6c8b807077f4070200a8fb4c6b771')

    assert pubkey == privatekey_to_publickey(privkey).hex()


def test_signer_sign():
    privkey = sha3(b'secret')  # 0x38e959391dD8598aE80d5d6D114a7822A09d313A
    message = b'message'
    # generated with Metamask's web3.personal.sign
    signature = decode_hex(
        '0x1eff8317c59ab169037f5063a5129bb1bab0299fef0b5621d866b07be59e2c0a'
        '6a404e88d3360fb58bd13daf577807c2cf9b6b26d80fc929c52e952769a460981c',
    )

    signer: Signer = LocalSigner(privkey)

    assert signer.sign(message) == signature


def test_recover():
    account = to_canonical_address('0x38e959391dD8598aE80d5d6D114a7822A09d313A')
    message = b'message'
    # generated with Metamask's web3.personal.sign
    signature = decode_hex(
        '0x1eff8317c59ab169037f5063a5129bb1bab0299fef0b5621d866b07be59e2c0a'
        '6a404e88d3360fb58bd13daf577807c2cf9b6b26d80fc929c52e952769a460981c',
    )

    assert recover(data=message, signature=signature) == account
