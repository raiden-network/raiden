# -*- coding: utf-8 -*
import pytest
import tempfile
import re
import os
import shutil

from raiden.utils import get_contract_path
from raiden.utils.solc import compile_files_cwd
from raiden.exceptions import ContractVersionMismatch

from raiden.blockchain.abi import CONTRACT_VERSION_RE, CONTRACT_MANAGER, CONTRACT_CHANNEL_MANAGER


def replace_contract_version(file_path, new_version):
    version_re = re.compile(CONTRACT_VERSION_RE)
    with open(file_path, 'r') as original:
        replaced = tempfile.NamedTemporaryFile()
        for line in original.readlines():
            if version_re.match(line):
                line = re.sub(r'[0-9]+\.[0-9]+\.[0-9\_]', new_version, line)
            replaced.write(line.encode())
        replaced.flush()
        shutil.copy2(replaced.name, file_path)


class TempSolidityDir:
    def __init__(self, original_directory, tmpdir):
        tempdir = tmpdir.mkdir(os.path.basename(original_directory))
        self.name = tempdir.strpath
        os.rmdir(self.name)  # directory must not exist when using shutil.copytree()
        shutil.copytree(original_directory, self.name)


@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
def test_deploy_contract(raiden_network, deploy_client, tmpdir):
    """Test deploying contract with different version than the one we have set in Registry.sol.
    This test makes sense only for geth backend, tester uses mocked Registry class.
    """
    contract_path = get_contract_path('Registry.sol')
    #  Create temporary directory to put all files required to compile the changed contract to.
    #  Why? Solidity uses first 40 characters of the file path as a library symbol.
    #  It would be nice to just do a copy of 'Registry.sol', replace version and include statements
    #  and then by path substitution argument of solc set the path to something like
    #  raiden-contracts=/path/to/your/raiden/source/contracts. But then if the path is too long,
    #  Python solidity compiler will fail because of duplicate library symbol.
    temp_dir = TempSolidityDir(os.path.dirname(contract_path), tmpdir)
    replaced_registry_path = os.path.join(temp_dir.name, 'Registry.sol')

    CONTRACT_MANAGER.get_contract_abi(CONTRACT_CHANNEL_MANAGER)

    replace_contract_version(replaced_registry_path, '0.0.31415')
    contracts = compile_files_cwd([replaced_registry_path])

    contract_proxy = deploy_client.deploy_solidity_contract(
        'Registry',
        contracts,
        dict(),
        None,
        contract_path=replaced_registry_path,
    )
    contract_address = contract_proxy.contract_address

    app0 = raiden_network[0]
    with pytest.raises(ContractVersionMismatch):
        app0.raiden.chain.registry(contract_address)
