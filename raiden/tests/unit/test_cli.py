# -*- coding: utf-8 -*-
from raiden.ui.cli import (
    check_json_rpc,
    init_minified_addr_checker,
    check_minified_address
)


class MockClient:

    def __init__(self, version):
        self.version_string = version

    def call(self, func):
        assert func == 'web3_clientVersion'
        return self.version_string


def test_check_json_rpc_geth():
    assert check_json_rpc(MockClient('Geth/v1.7.3-unstable-e9295163/linux-amd64/go1.9.1'))
    assert check_json_rpc(MockClient('Geth/v1.7.2-unstable-e9295163/linux-amd64/go1.9.1'))
    assert check_json_rpc(MockClient('Geth/v1.8.2-unstable-e9295163/linux-amd64/go1.9.1'))
    assert check_json_rpc(MockClient('Geth/v2.0.3-unstable-e9295163/linux-amd64/go1.9.1'))
    assert check_json_rpc(MockClient('Geth/v11.55.86-unstable-e9295163/linux-amd64/go1.9.1'))
    assert check_json_rpc(MockClient('Geth/v999.999.999-unstable-e9295163/linux-amd64/go1.9.1'))

    assert not check_json_rpc(MockClient('Geth/v1.7.1-unstable-e9295163/linux-amd64/go1.9.1'))
    assert not check_json_rpc(MockClient('Geth/v0.7.1-unstable-e9295163/linux-amd64/go1.9.1'))
    assert not check_json_rpc(MockClient('Geth/v0.0.0-unstable-e9295163/linux-amd64/go1.9.1'))
    assert not check_json_rpc(MockClient('Geth/v0.0.0-unstable-e9295163/linux-amd64/go1.9.1'))


def test_check_json_rpc_parity():
    assert check_json_rpc(MockClient(
        'Parity//v1.7.6-stable-19535333c-20171013/x86_64-linux-gnu/rustc1.20.0'
    ))
    assert check_json_rpc(MockClient(
        'Parity//v1.7.7-stable-19535333c-20171013/x86_64-linux-gnu/rustc1.20.0'
    ))
    assert check_json_rpc(MockClient(
        'Parity//v1.8.7-stable-19535333c-20171013/x86_64-linux-gnu/rustc1.20.0'
    ))
    assert check_json_rpc(MockClient(
        'Parity//v2.9.7-stable-19535333c-20171013/x86_64-linux-gnu/rustc1.20.0'
    ))
    assert check_json_rpc(MockClient(
        'Parity//v23.94.75-stable-19535333c-20171013/x86_64-linux-gnu/rustc1.20.0'
    ))
    assert check_json_rpc(MockClient(
        'Parity//v99.994.975-stable-19535333c-20171013/x86_64-linux-gnu/rustc1.20.0'
    ))

    assert not check_json_rpc(MockClient(
        'Parity//v1.7.5-stable-19535333c-20171013/x86_64-linux-gnu/rustc1.20.0'
    ))
    assert not check_json_rpc(MockClient(
        'Parity//v1.5.1-stable-19535333c-20171013/x86_64-linux-gnu/rustc1.20.0'
    ))
    assert not check_json_rpc(MockClient(
        'Parity//v0.7.1-stable-19535333c-20171013/x86_64-linux-gnu/rustc1.20.0'
    ))
    assert not check_json_rpc(MockClient(
        'Parity//v0.8.7-stable-19535333c-20171013/x86_64-linux-gnu/rustc1.20.0'
    ))
    assert not check_json_rpc(MockClient(
        'Parity//v0.0.0-stable-19535333c-20171013/x86_64-linux-gnu/rustc1.20.0'
    ))


def test_minified_address_checker():
    re = init_minified_addr_checker()
    assert check_minified_address('9bed7fd1', re)
    assert check_minified_address('8c1d1f23', re)
    assert not check_minified_address('xxxxxx', re)
    assert not check_minified_address('123zzz', re)
    assert not check_minified_address('$@$^$', re)
