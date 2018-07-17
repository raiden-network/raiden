from raiden.utils import (
    is_minified_address,
    is_supported_client,
)
from raiden.constants import EthClient


def test_check_json_rpc_geth():
    g1, client = is_supported_client('Geth/v1.7.3-unstable-e9295163/linux-amd64/go1.9.1')
    g2, _ = is_supported_client('Geth/v1.7.2-unstable-e9295163/linux-amd64/go1.9.1')
    g3, _ = is_supported_client('Geth/v1.8.2-unstable-e9295163/linux-amd64/go1.9.1')
    g4, _ = is_supported_client('Geth/v2.0.3-unstable-e9295163/linux-amd64/go1.9.1')
    g5, _ = is_supported_client('Geth/v11.55.86-unstable-e9295163/linux-amd64/go1.9.1')
    g6, _ = is_supported_client('Geth/v999.999.999-unstable-e9295163/linux-amd64/go1.9.1')
    assert client == EthClient.GETH
    assert all([g1, g2, g3, g4, g5, g6])

    b1, client = is_supported_client('Geth/v1.7.1-unstable-e9295163/linux-amd64/go1.9.1')
    b2, _ = is_supported_client('Geth/v0.7.1-unstable-e9295163/linux-amd64/go1.9.1')
    b3, _ = is_supported_client('Geth/v0.0.0-unstable-e9295163/linux-amd64/go1.9.1')
    b4, _ = is_supported_client('Geth/v0.0.0-unstable-e9295163/linux-amd64/go1.9.1')
    assert not client
    assert not any([b1, b2, b3, b4])


def test_check_json_rpc_parity():
    g1, client = is_supported_client(
        'Parity//v1.7.6-stable-19535333c-20171013/x86_64-linux-gnu/rustc1.20.0',
    )
    g2, _ = is_supported_client(
        'Parity//v1.7.7-stable-19535333c-20171013/x86_64-linux-gnu/rustc1.20.0',
    )
    g3, _ = is_supported_client(
        'Parity//v1.8.7-stable-19535333c-20171013/x86_64-linux-gnu/rustc1.20.0',
    )
    g4, _ = is_supported_client(
        'Parity//v2.9.7-stable-19535333c-20171013/x86_64-linux-gnu/rustc1.20.0',
    )
    g5, _ = is_supported_client(
        'Parity//v23.94.75-stable-19535333c-20171013/x86_64-linux-gnu/rustc1.20.0',
    )
    g6, _ = is_supported_client(
        'Parity//v99.994.975-stable-19535333c-20171013/x86_64-linux-gnu/rustc1.20.0',
    )
    assert client == EthClient.PARITY
    assert all([g1, g2, g3, g4, g5, g6])

    b1, client = is_supported_client(
        'Parity//v1.7.5-stable-19535333c-20171013/x86_64-linux-gnu/rustc1.20.0',
    )
    b2, _ = is_supported_client(
        'Parity//v1.5.1-stable-19535333c-20171013/x86_64-linux-gnu/rustc1.20.0',
    )
    b3, _ = is_supported_client(
        'Parity//v0.7.1-stable-19535333c-20171013/x86_64-linux-gnu/rustc1.20.0',
    )
    b4, _ = is_supported_client(
        'Parity//v0.8.7-stable-19535333c-20171013/x86_64-linux-gnu/rustc1.20.0',
    )
    b5, _ = is_supported_client(
        'Parity//v0.0.0-stable-19535333c-20171013/x86_64-linux-gnu/rustc1.20.0',
    )
    assert not client
    assert not any([b1, b2, b3, b4, b5])


def test_minified_address_checker():
    assert is_minified_address('9bed7fd1')
    assert is_minified_address('8c1d1f23')
    assert not is_minified_address('xxxxxx')
    assert not is_minified_address('123zzz')
    assert not is_minified_address('$@$^$')
