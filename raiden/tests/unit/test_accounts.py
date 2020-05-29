import logging
import os
from random import randint
from unittest.mock import patch
from uuid import UUID

import pytest
from eth_keyfile.keyfile import decode_keyfile_json
from eth_utils import decode_hex, encode_hex

from raiden.accounts import Account, AccountManager, KeystoreFileNotFound
from raiden.ui.prompt import unlock_account_with_passwordfile
from raiden.utils.keys import privatekey_to_address, privatekey_to_publickey
from raiden.utils.system import get_project_root

# use random file name so tests can run in parallel
KEYFILE_INACCESSIBLE = "UTC--2017-06-20T16-33-00.{:09d}Z--inaccessible".format(
    randint(0, 999999999)
)
KEYFILE_INVALID = "UTC--2017-06-20T16-06-00.000000000Z--invalid"


@pytest.fixture(scope="module")
def keystore_mock():
    keystore = os.path.join(get_project_root(), "tests", "test_files")
    # Create inaccessible keyfile
    inaccessible_file = os.path.join(keystore, KEYFILE_INACCESSIBLE)
    if not os.path.exists(inaccessible_file):
        open(inaccessible_file, "w").close()
    os.chmod(inaccessible_file, 0)
    yield keystore
    # Cleanup to leave no undeletable files behind
    os.chmod(inaccessible_file, 0o600)
    os.unlink(inaccessible_file)


def test_get_accounts(keystore_mock):
    account_manager = AccountManager(keystore_mock)
    expected_accounts = {
        "0x0d5a0e4FECE4b84365b9B8DbA6e6D41348C73645": os.path.join(
            keystore_mock,
            "UTC--2016-10-26T16-55-53.551024336Z--0d5a0e4fece4b84365b9b8dba6e6d41348c73645",
        ),
        "0x3593403033d18b82f7b4a0F18e1ED24623D23b20": os.path.join(
            keystore_mock, "valid_keystorefile_with_unexpected_name"
        ),
    }
    assert expected_accounts == account_manager.accounts


def test_get_account_in_keystore(keystore_mock):
    account_manager = AccountManager(keystore_mock)
    assert account_manager.address_in_keystore("0x0d5a0e4FECE4b84365b9B8DbA6e6D41348C73645")
    assert account_manager.address_in_keystore("0x3593403033d18b82f7b4a0F18e1ED24623D23b20")
    assert not account_manager.address_in_keystore("0xa05934d3033D18b82F7b4AdF18E1eD24E3D23b19")
    assert not account_manager.address_in_keystore(None)


def test_get_privkey(keystore_mock):
    account_manager = AccountManager(keystore_mock)
    assert "0xf696ecb5c767263c797a035db6f6008d38d852960ed33a491a58390b003fb605" == encode_hex(
        account_manager.get_privkey("0x0d5a0e4FECE4b84365b9B8DbA6e6D41348C73645", "123")
    )
    assert "0x36fa966441f259501110ba88f8212dfd7f8bacb07862a7d5cf8f31c1a64551e5" == encode_hex(
        account_manager.get_privkey("0x3593403033d18b82f7b4a0F18e1ED24623D23b20", "123")
    )

    # failures
    with pytest.raises(ValueError) as exc:
        account_manager.get_privkey("0x3593403033d18b82f7b4a0F18e1ED24623D23b20", "456")
    assert "MAC mismatch" in str(exc.value)
    with pytest.raises(KeystoreFileNotFound) as exc:
        account_manager.get_privkey("0xa05934d3033D18b82F7b4AdF18E1eD24E3D23b19", "123")
    assert "Keystore file not found for 0xa05934d3033D18b82F7b4AdF18E1eD24E3D23b19" in str(
        exc.value
    )


def test_account_manager_invalid_files(keystore_mock, caplog):
    with caplog.at_level(logging.DEBUG):
        AccountManager(keystore_mock)

    logs = [
        (
            "The account file is not valid JSON format",
            KEYFILE_INVALID,
            "Expecting value: line 1 column 1 (char 0)",
        ),
        ("Can not read account file (errno=13)", KEYFILE_INACCESSIBLE, "Permission denied"),
    ]

    for msg, file_name, reason in logs:
        for record in caplog.records:
            message = record.getMessage()
            if msg in message and file_name in message and reason in message:
                break
        else:
            assert False, f"'{msg}' not in log messages"


def test_account_manager_invalid_directory(caplog):
    with patch.object(os, "listdir") as mock_listdir:
        mock_listdir.side_effect = OSError
        AccountManager("/some/path")

    logs = [("Unable to list the specified directory", "/some/path", "")]

    for msg, path, reason in logs:
        for record in caplog.records:
            message = record.getMessage()
            if msg in message and path in message and reason in message:
                break
        else:
            assert False, f"'{msg}' not in log messages"


def test_unlock_account_with_passwordfile(keystore_mock):
    account_manager = AccountManager(keystore_mock)
    password_file_path = os.path.join(keystore_mock, "passwordfile.txt")

    with open(password_file_path, "r") as password_file:
        privkey = unlock_account_with_passwordfile(
            account_manager=account_manager,
            address_hex="0x0d5a0e4FECE4b84365b9B8DbA6e6D41348C73645",
            password_file=password_file,
        )
    assert privkey


KEYSTORE = {
    "address": "da0100629c3d61531cbd1c0d8fc590a90dcd5157",
    "crypto": {
        "cipher": "aes-128-ctr",
        "ciphertext": "46054df9d113b8bb449b5d8b9b5e6c3115d45d684a21e94b4eec9c5842377163",
        "cipherparams": {"iv": "7a634a007f4b64abdc1da28a7fec09ca"},
        "kdf": "scrypt",
        "kdfparams": {
            "dklen": 32,
            "n": 262144,
            "p": 1,
            "r": 8,
            "salt": "1981e90b6d5295cb7495b394dcf577d984496a8b4798ec1bdbe40a81d9487c57",
        },
        "mac": "48f816de2d570bd813510af71f015d967750dc8ba305bf39b2876d16d28dda0a",
    },
    "id": "625f9239-07e7-42e0-8ab8-0516a7bd9d93",
    "version": 3,
}
PASSWORD = "supersecret"
PRIVKEY = decode_keyfile_json(KEYSTORE, PASSWORD)


def test_account_from_keystore():
    keystore = dict(KEYSTORE)
    account = Account(keystore)
    assert account.locked
    assert account.privkey is None
    assert account.uuid == KEYSTORE["id"]
    assert account.address == decode_hex(KEYSTORE["address"])

    with pytest.raises(ValueError):
        account.unlock("wrong-password")
    assert account.locked

    account.unlock(PASSWORD)
    account.unlock("wrong-password")  # ignored as the account is not locked
    assert not account.locked
    assert account.privkey == PRIVKEY
    assert account.pubkey == privatekey_to_publickey(PRIVKEY)

    account.lock()
    assert account.locked
    assert account.privkey is None
    assert account.pubkey is None


def test_account_from_keystore_and_password():
    keystore = dict(KEYSTORE)
    keystore.pop("address")
    account = Account(keystore, PASSWORD)

    assert not account.locked
    assert account.address == decode_hex(KEYSTORE["address"])


def test_account_from_keystore_without_address_and_uuid():
    keystore = dict(KEYSTORE)
    keystore.pop("address")
    keystore.pop("id")
    account = Account(keystore)
    assert account.address is None

    account.unlock(PASSWORD)
    assert account.address == privatekey_to_address(PRIVKEY)
    assert account.uuid is None
    account.uuid = new_uuid = UUID(hex="1234567890abcdef1234567890abcdef")
    assert str(new_uuid) in repr(account)
