# -*- coding: utf-8 -*-

from coincurve import PrivateKey

def privtopub(raw_privkey):
    pub = PrivateKey.from_hex(raw_privkey).public_key.format(compressed=False)
    return pub[1:]
