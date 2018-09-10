#!/usr/bin/env python3
import json
import logging
import os
from datetime import datetime
from json import JSONEncoder

import click
from coincurve import PrivateKey
from ethereum.tools import keys
from ethereum.tools.keys import encode_hex, make_keystore_json, sha3


class BytesJSONEncoder(JSONEncoder):
    def default(self, o):
        if isinstance(o, bytes):
            return o.decode('UTF-8')
        return super().default(o)


@click.command()
@click.option("--date-string", default=datetime.now().isoformat(), show_default=True)
@click.option("--key-label")
@click.option("-o", "--output-dir", show_default=True, default=".",
              type=click.Path(exists=True, file_okay=False, writable=True))
@click.argument("password")
@click.argument("private_key_seed", nargs=-1)
def main(password, private_key_seed, date_string, key_label, output_dir):
    private_key_bin = sha3("".join(seed for seed in private_key_seed).encode("UTF-8"))

    password = password.encode("UTF-8")

    key = make_keystore_json_patched(private_key_bin, password)
    key['address'] = encode_hex(privatekey_to_address(private_key_bin))

    filename = "UTC--{date}--{label}".format(
        date=date_string,
        label=key_label if key_label else key['address'],
    )
    filepath = os.path.abspath(os.path.join(os.path.abspath(output_dir), filename))

    with open(filepath, "w") as f:
        json.dump(key, f, cls=BytesJSONEncoder)

    print("0x{}".format(key['address']))


def privatekey_to_address(private_key_bin):
    return sha3(PrivateKey(private_key_bin).public_key.format(compressed=False)[1:])[12:]


def make_keystore_json_patched(private_key, password):
    # Fix py3 bytes/string incompatibility in `make_keystore_json()`
    # See: https://github.com/ethereum/pyethereum/issues/758
    _encode_hex = keys.encode_hex
    setattr(keys, 'encode_hex', lambda *args: _encode_hex(*args).encode('ASCII'))
    try:
        return make_keystore_json(private_key, password)
    finally:
        setattr(keys, 'encode_hex', _encode_hex)


if __name__ == "__main__":
    logging.basicConfig(level=logging.ERROR)
    main()
