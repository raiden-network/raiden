from raiden.utils import privtopub, sha3


def test_privtopub():
    privkey = sha3(b'secret')
    pubkey = ('c283b0507c4ec6903a49fac84a5aead951f3c38b2c72b69da8a70a5bac91e9c'
              '705f70c7554b26e82b90d2d1bbbaf711b10c6c8b807077f4070200a8fb4c6b771')

    assert pubkey == privtopub(privkey).hex()
