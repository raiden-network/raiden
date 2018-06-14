import json

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


def test_cli_smoketest():
    runner = CliRunner()
    result = runner.invoke(run, ["smoketest"])
    assert result.exit_code == 0
    assert "[5/5] smoketest successful" in result.output


def test_cli_version():
    runner = CliRunner()
    result = runner.invoke(run, ["version"])
    assert result.exit_code == 0
    result_json = json.loads(result.output)
    result_expected_keys = ["raiden", "python_implementation", "python_version", "system"]
    for expected_key in result_expected_keys:
        assert expected_key in result_json


def test_cli_password_file(private_keys, blockchain_services, tmpdir):
    chain = blockchain_services.blockchain_services[0]
    my_address = privatekey_to_address(private_keys[0])
    data_dir = encode_hex(private_keys[0])[:8]
    assert data_dir == "1212"
    runner = CliRunner()
    result = runner.invoke(run, ["--keystore-path", tmpdir])
    assert result.exit_code == 0
    assert chain == "a"
    assert my_address == "b"
