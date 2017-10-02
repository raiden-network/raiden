# -*- coding: utf-8 -*-

import bitcoin


def privtopub(raw_privkey):
    pubkey = bitcoin.privtopub(raw_privkey)
    raw_pubkey = bitcoin.encode_pubkey(pubkey, 'bin_electrum')
    assert len(raw_pubkey) == 64
    return raw_pubkey
