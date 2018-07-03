import json
import os

from click.testing import CliRunner
from raiden.ui.cli import run

from raiden.utils import (
    privatekey_to_address,
    encode_hex,
)

"""
def blockchain_backend(
        request,
        deploy_key,
        deploy_client,
        private_keys,
        blockchain_private_keys,
        blockchain_p2p_ports,
        blockchain_rpc_ports,
        tmpdir,
        random_marker,
        blockchain_type,
):
"""


def DISABLE_test_cli_smoketest():
    runner = CliRunner()
    result = runner.invoke(run, ["smoketest"])
    assert result.exit_code == 0
    assert "[5/5] smoketest successful" in result.output


def DISABLE_test_cli_version():
    runner = CliRunner()
    result = runner.invoke(run, ["version"])
    assert result.exit_code == 0
    result_json = json.loads(result.output)
    result_expected_keys = ["raiden", "python_implementation", "python_version", "system"]
    for expected_key in result_expected_keys:
        assert expected_key in result_json


def DISABLE_test_cli_password_file(private_keys, blockchain_private_keys, blockchain_services, tmpdir):
    chain = blockchain_services.blockchain_services[0]
    print(tmpdir)
    print(encode_hex(blockchain_private_keys[0])[:8])
    my_address = privatekey_to_address(private_keys[0])
    data_dir = chain.private_key[:8]
    assert data_dir == "1212"
    runner = CliRunner()
    result = runner.invoke(run, ["--keystore-path", tmpdir])
    assert result.exit_code == 0
    assert chain == "a"
    assert my_address == "b"


def test_cli_keystore_path(blockchain_private_keys, blockchain_services, tmpdir):
    geth_dir = os.path.join(tmpdir, encode_hex(blockchain_private_keys[0])[:8])
    keystore_path = os.path.join(geth_dir, 'keystore')
    password_file_path = os.path.join(geth_dir, 'pw')
    print("Reading password file...")
    with open(password_file_path, 'r') as f:
        print(f.readlines())

    print(keystore_path)
    runner = CliRunner()
    result = runner.invoke(run, ["--keystore-path", keystore_path,
                                 "--password-file", password_file_path,
                                 "--nat=none"])
    import time
    time.sleep(10)
    assert "aaiden" in result.output
    print(result.output)

