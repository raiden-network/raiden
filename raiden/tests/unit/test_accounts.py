# -*- coding: utf-8 -*-
import os
import pytest

from ethereum.utils import encode_hex
from raiden.accounts import AccountManager
from raiden.utils import get_project_root

test_keystore = os.path.join(get_project_root(), 'tests', 'test_files')


def test_get_accounts():
    account_manager = AccountManager(test_keystore)
    expected_accounts = {
        '0d5a0e4fece4b84365b9b8dba6e6d41348c73645': os.path.join(
            test_keystore,
            'UTC--2016-10-26T16-55-53.551024336Z--0d5a0e4fece4b84365b9b8dba6e6d41348c73645'
        ),
        '3593403033d18b82f7b4a0f18e1ed24623d23b20': os.path.join(
            test_keystore,
            'valid_keystorefile_with_unexpected_name'
        )
    }
    assert expected_accounts == account_manager.accounts


def test_get_account_in_keystore():
    account_manager = AccountManager(test_keystore)
    assert account_manager.address_in_keystore('0d5a0e4fece4b84365b9b8dba6e6d41348c73645')
    assert account_manager.address_in_keystore('0x0d5a0e4fece4b84365b9b8dba6e6d41348c73645')
    assert account_manager.address_in_keystore('3593403033d18b82f7b4a0f18e1ed24623d23b20')
    assert account_manager.address_in_keystore('0x3593403033d18b82f7b4a0f18e1ed24623d23b20')
    assert not account_manager.address_in_keystore('a05934d3033d18b82f7b4adf18e1ed24e3d23b19')


def test_get_privkey():
    account_manager = AccountManager(test_keystore)
    'f696ecb5c767263c797a035db6f6008d38d852960ed33a491a58390b003fb605' == encode_hex(
        account_manager.get_privkey('0d5a0e4fece4b84365b9b8dba6e6d41348c73645', '123')
    )
    'f696ecb5c767263c797a035db6f6008d38d852960ed33a491a58390b003fb605' == encode_hex(
        account_manager.get_privkey('0x0d5a0e4fece4b84365b9b8dba6e6d41348c73645', '123')
    )
    '36fa966441f259501110ba88f8212dfd7f8bacb07862a7d5cf8f31c1a64551e5' == encode_hex(
        account_manager.get_privkey('3593403033d18b82f7b4a0f18e1ed24623d23b20', '123')
    )
    '36fa966441f259501110ba88f8212dfd7f8bacb07862a7d5cf8f31c1a64551e5' == encode_hex(
        account_manager.get_privkey('0x3593403033d18b82f7b4a0f18e1ed24623d23b20', '123')
    )

    # failures
    with pytest.raises(ValueError) as exc:
        account_manager.get_privkey('0x3593403033d18b82f7b4a0f18e1ed24623d23b20', '456')
    assert 'MAC mismatch. Password incorrect?' in exc.value
    with pytest.raises(ValueError) as exc:
        account_manager.get_privkey('a05934d3033d18b82f7b4adf18e1ed24e3d23b19', '123')
    assert 'Keystore file not found for a05934d3033d18b82f7b4adf18e1ed24e3d23b19' in exc.value
