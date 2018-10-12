import logging
import os
from unittest.mock import patch

import pytest
from eth_utils import encode_hex

from raiden.accounts import AccountManager
from raiden.utils import get_project_root

KEYFILE_INACCESSIBLE = 'UTC--2017-06-20T16-33-00.000000000Z--inaccessible'
KEYFILE_INVALID = 'UTC--2017-06-20T16-06-00.000000000Z--invalid'


@pytest.yield_fixture(scope='module')
def test_keystore():
    keystore = os.path.join(get_project_root(), 'tests', 'test_files')
    # Create inaccessible keyfile
    inaccessible_file = os.path.join(keystore, KEYFILE_INACCESSIBLE)
    if not os.path.exists(inaccessible_file):
        open(inaccessible_file, 'w').close()
    os.chmod(inaccessible_file, 0)
    yield keystore
    # Cleanup to leave no undeletable files behind
    os.chmod(inaccessible_file, 0o600)
    os.unlink(inaccessible_file)


def test_get_accounts(test_keystore):
    account_manager = AccountManager(test_keystore)
    expected_accounts = {
        '0x0d5a0e4fece4b84365b9b8dba6e6d41348c73645': os.path.join(
            test_keystore,
            'UTC--2016-10-26T16-55-53.551024336Z--0d5a0e4fece4b84365b9b8dba6e6d41348c73645',
        ),
        '0x3593403033d18b82f7b4a0f18e1ed24623d23b20': os.path.join(
            test_keystore,
            'valid_keystorefile_with_unexpected_name',
        ),
    }
    assert expected_accounts == account_manager.accounts


def test_get_account_in_keystore(test_keystore):
    account_manager = AccountManager(test_keystore)
    assert account_manager.address_in_keystore('0d5a0e4fece4b84365b9b8dba6e6d41348c73645')
    assert account_manager.address_in_keystore('0x0d5a0e4fece4b84365b9b8dba6e6d41348c73645')
    assert account_manager.address_in_keystore('0x0D5A0E4fece4b84365b9b8dba6e6d41348c73645')
    assert account_manager.address_in_keystore('3593403033d18b82f7b4a0f18e1ed24623d23b20')
    assert account_manager.address_in_keystore('0x3593403033d18b82f7b4a0f18e1ed24623d23b20')
    assert not account_manager.address_in_keystore('a05934d3033d18b82f7b4adf18e1ed24e3d23b19')


def test_get_privkey(test_keystore):
    account_manager = AccountManager(test_keystore)
    assert '0xf696ecb5c767263c797a035db6f6008d38d852960ed33a491a58390b003fb605' == encode_hex(
        account_manager.get_privkey('0d5a0e4fece4b84365b9b8dba6e6d41348c73645', '123'),
    )
    assert '0xf696ecb5c767263c797a035db6f6008d38d852960ed33a491a58390b003fb605' == encode_hex(
        account_manager.get_privkey('0x0d5a0e4fece4b84365b9b8dba6e6d41348c73645', '123'),
    )
    assert '0x36fa966441f259501110ba88f8212dfd7f8bacb07862a7d5cf8f31c1a64551e5' == encode_hex(
        account_manager.get_privkey('3593403033d18b82f7b4a0f18e1ed24623d23b20', '123'),
    )
    assert '0x36fa966441f259501110ba88f8212dfd7f8bacb07862a7d5cf8f31c1a64551e5' == encode_hex(
        account_manager.get_privkey('0x3593403033d18b82f7b4a0f18e1ed24623d23b20', '123'),
    )

    # failures
    with pytest.raises(ValueError) as exc:
        account_manager.get_privkey('0x3593403033d18b82f7b4a0f18e1ed24623d23b20', '456')
    assert 'MAC mismatch' in str(exc.value)
    with pytest.raises(ValueError) as exc:
        account_manager.get_privkey('a05934d3033d18b82f7b4adf18e1ed24e3d23b19', '123')
    assert (
        'Keystore file not found for 0xa05934d3033d18b82f7b4adf18e1ed24e3d23b19' in str(exc.value)
    )


def test_account_manager_invalid_files(test_keystore, caplog):
    with caplog.at_level(logging.DEBUG):
        AccountManager(test_keystore)

    for msg, file_name, reason in [
        ('The account file is not valid JSON format',
         KEYFILE_INVALID,
         'Expecting value: line 1 column 1 (char 0)'),
        ('Can not read account file (errno=13)', KEYFILE_INACCESSIBLE, 'Permission denied'),
    ]:
        for record in caplog.records:
            message = record.getMessage()
            if msg in message and file_name in message and reason in message:
                break
        else:
            assert False, "'{}' not in log messages".format(msg)


def test_account_manager_invalid_directory(caplog):
    with patch.object(os, 'listdir') as mock_listdir:
        mock_listdir.side_effect = OSError
        AccountManager('/some/path')

    for msg, path, reason in [
        ('Unable to list the specified directory', '/some/path', ''),
    ]:
        for record in caplog.records:
            message = record.getMessage()
            if msg in message and path in message and reason in message:
                break
        else:
            assert False, "'{}' not in log messages".format(msg)
