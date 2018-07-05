import os
import re
import subprocess

from eth_utils import decode_hex
from solc import compile_files, get_solc_version
from raiden_contracts.constants import CONTRACT_HUMAN_STANDARD_TOKEN
from raiden_contracts.contract_manager import CONTRACT_MANAGER

from raiden.constants import MIN_REQUIRED_SOLC


def solidity_resolve_address(hex_code, library_symbol, library_address):
    """ Change the bytecode to use the given library address.

    Args:
        hex_code (bin): The bytecode encoded in hexadecimal.
        library_name (str): The library that will be resolved.
        library_address (str): The address of the library.

    Returns:
        bin: The bytecode encoded in hexadecimal with the library references
            resolved.
    """
    if library_address.startswith('0x'):
        raise ValueError('Address should not contain the 0x prefix')

    try:
        decode_hex(library_address)
    except TypeError:
        raise ValueError(
            'library_address contains invalid characters, it must be hex encoded.')

    if len(library_symbol) != 40 or len(library_address) != 40:
        raise ValueError('Address with wrong length')

    return hex_code.replace(library_symbol, library_address)


def solidity_resolve_symbols(hex_code, libraries):
    symbol_address = {
        solidity_library_symbol(library_name): address
        for library_name, address in libraries.items()
    }

    for unresolved in solidity_unresolved_symbols(hex_code):
        address = symbol_address[unresolved]
        hex_code = solidity_resolve_address(hex_code, unresolved, address)

    return hex_code


def solidity_library_symbol(library_name):
    """ Return the symbol used in the bytecode to represent the `library_name`. """
    # the symbol is always 40 characters in length with the minimum of two
    # leading and trailing underscores
    length = min(len(library_name), 36)

    library_piece = library_name[:length]
    hold_piece = '_' * (36 - length)

    return '__{library}{hold}__'.format(
        library=library_piece,
        hold=hold_piece,
    )


def solidity_unresolved_symbols(hex_code):
    """ Return the unresolved symbols contained in the `hex_code`.

    Note:
        The binary representation should not be provided since this function
        relies on the fact that the '_' is invalid in hex encoding.

    Args:
        hex_code (str): The bytecode encoded as hexadecimal.
    """
    return set(re.findall(r"_.{39}", hex_code))


def compile_files_cwd(*args, **kwargs):
    """change working directory to contract's dir in order to avoid symbol
    name conflicts"""
    # get root directory of the contracts
    compile_wd = os.path.commonprefix(args[0])
    # edge case - compiling a single file
    if os.path.isfile(compile_wd):
        compile_wd = os.path.dirname(compile_wd)
    # remove prefix from the files
    if compile_wd[-1] is not '/':
        compile_wd += '/'
    file_list = [
        x.replace(compile_wd, '')
        for x in args[0]
    ]
    cwd = os.getcwd()
    try:
        os.chdir(compile_wd)
        compiled_contracts = compile_files(file_list, **kwargs)
    finally:
        os.chdir(cwd)
    return compiled_contracts


def validate_solc():
    if get_solc_version() is None:
        raise RuntimeError(
            "Couldn't find the solc in the current $PATH.\n"
            "Make sure the solidity compiler is installed and available on your $PATH.",
        )

    try:
        compile_files(
            [CONTRACT_MANAGER.get_contract_path(CONTRACT_HUMAN_STANDARD_TOKEN)],
            'HumanStandardToken',
            optimize=False,
        )
    except subprocess.CalledProcessError as e:
        msg = (
            'The solidity compiler failed to execute. Please make sure that you\n'
            'are using the binary version of the compiler (solc-js is not compatible)\n'
            'and that the version is >= {}'.format(MIN_REQUIRED_SOLC)
        )

        if e.output:
            msg += (
                '\n'
                'Output: ' + e.output
            )

        raise RuntimeError(msg)

    except OSError as e:
        msg = (
            'The solidity compiler failed to execute. Please make sure the\n'
            'binary is compatible with your architecture and you can execute it.'
        )

        child_traceback = getattr(e, 'child_traceback', None)
        if child_traceback:
            msg += (
                '\n'
                'Traceback: ' + child_traceback
            )

        raise RuntimeError(msg)
