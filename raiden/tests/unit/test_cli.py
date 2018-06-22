from raiden.utils import (
    is_minified_address,
    is_supported_client,
)


class MockVersion:
    def __init__(self, node):
        self.node = node


class MockWeb3:
    def __init__(self, version):
        self.version = version


class MockClient:
    def __init__(self, version):
        version = MockVersion(version)
        self.web3 = MockWeb3(version)


def test_check_json_rpc_geth():
    assert is_supported_client('Geth/v1.7.3-unstable-e9295163/linux-amd64/go1.9.1')
    assert is_supported_client('Geth/v1.7.2-unstable-e9295163/linux-amd64/go1.9.1')
    assert is_supported_client('Geth/v1.8.2-unstable-e9295163/linux-amd64/go1.9.1')
    assert is_supported_client('Geth/v2.0.3-unstable-e9295163/linux-amd64/go1.9.1')
    assert is_supported_client('Geth/v11.55.86-unstable-e9295163/linux-amd64/go1.9.1')
    assert is_supported_client('Geth/v999.999.999-unstable-e9295163/linux-amd64/go1.9.1')

    assert not is_supported_client('Geth/v1.7.1-unstable-e9295163/linux-amd64/go1.9.1')
    assert not is_supported_client('Geth/v0.7.1-unstable-e9295163/linux-amd64/go1.9.1')
    assert not is_supported_client('Geth/v0.0.0-unstable-e9295163/linux-amd64/go1.9.1')
    assert not is_supported_client('Geth/v0.0.0-unstable-e9295163/linux-amd64/go1.9.1')


def test_check_json_rpc_parity():
    assert is_supported_client(
        'Parity//v1.7.6-stable-19535333c-20171013/x86_64-linux-gnu/rustc1.20.0',
    )
    assert is_supported_client(
        'Parity//v1.7.7-stable-19535333c-20171013/x86_64-linux-gnu/rustc1.20.0',
    )
    assert is_supported_client(
        'Parity//v1.8.7-stable-19535333c-20171013/x86_64-linux-gnu/rustc1.20.0',
    )
    assert is_supported_client(
        'Parity//v2.9.7-stable-19535333c-20171013/x86_64-linux-gnu/rustc1.20.0',
    )
    assert is_supported_client(
        'Parity//v23.94.75-stable-19535333c-20171013/x86_64-linux-gnu/rustc1.20.0',
    )
    assert is_supported_client(
        'Parity//v99.994.975-stable-19535333c-20171013/x86_64-linux-gnu/rustc1.20.0',
    )

    assert not is_supported_client(
        'Parity//v1.7.5-stable-19535333c-20171013/x86_64-linux-gnu/rustc1.20.0',
    )
    assert not is_supported_client(
        'Parity//v1.5.1-stable-19535333c-20171013/x86_64-linux-gnu/rustc1.20.0',
    )
    assert not is_supported_client(
        'Parity//v0.7.1-stable-19535333c-20171013/x86_64-linux-gnu/rustc1.20.0',
    )
    assert not is_supported_client(
        'Parity//v0.8.7-stable-19535333c-20171013/x86_64-linux-gnu/rustc1.20.0',
    )
    assert not is_supported_client(
        'Parity//v0.0.0-stable-19535333c-20171013/x86_64-linux-gnu/rustc1.20.0',
    )


def test_minified_address_checker():
    assert is_minified_address('9bed7fd1')
    assert is_minified_address('8c1d1f23')
    assert not is_minified_address('xxxxxx')
    assert not is_minified_address('123zzz')
    assert not is_minified_address('$@$^$')
