import pathlib

from installer.utils import create_symlink, create_desktop_icon, download_file


def download_eth_binary(target_path: pathlib.Path) -> pathlib.Path:
    """Download the latest binary of 'the' ethereum client.

    Flip a coin on whether to use geth or parity? User selection would be
    fine too, I guess.

    TODO: This is a stub.
    """
    return download_file(target_path, "version_string")


def install_eth_binary(archive: pathlib.Path, target_path: pathlib.Path) -> pathlib.Path:
    """ Extract a downloaded binary from its archive and install it in the given directory.

    TODO: This is a stub.
    """
    return archive, target_path


def configure_eth_client(bin_path: pathlib.Path, method: str):
    """Configure the Ethereum client using the given method.

    TODO: This is a stub.
    """
    return bin_path, method


def install_private_chain() -> None:
    """Install a private chain and connect to it.

    TODO: This is a stub (and will probably remain one for quite a while).
    """


def install_eth_client(download_cache_dir: pathlib.Path, bin_path: pathlib.Path) -> None :
    """Execute the Ethereum Client installation step.

    TODO: This is a stub.
    """
    # TODO: User input require input validation.
    eth_client = input("Use local eth client? [Y/n]")
    if not eth_client:
        eth_archive_path = download_eth_binary(download_cache_dir)
        eth_client_path = install_eth_binary(eth_archive_path, bin_path)
        make_symlink = input("Create a symbolic link at /usr/local/bin for the Ethereum client? [Y/n]")
        if make_symlink:
            create_symlink(eth_client_path)

        # TODO: User input require input validation.
        desktop_icon = input('Would you like to create a desktop icon for the Ethereum client?')
        if desktop_icon:
            create_desktop_icon(eth_client_path)
    else:
        # TODO: User input require input validation.
        eth_client_path = input('Please specify the path to the eth client: [/usr/local/bin/geth]')

    # Determine which connection method we should use.
    print(
        "\nPlease choose a connection option:"
        "   [1] Connect to Infura"
        "   [2] Connect to an existing Ethereum Client"
        "   [3] Connecto to an existing Raiden Client (launches WebUI after installation)"
        "   [4] Use local Ethereum Client and synchronize network"
        "   [5] Install a private chain\n"
    )
    connection_method = input("Your selection: [1]")

    if connection_method == 5:
        install_private_chain()
    else:
        configure_eth_client(eth_client_path, connection_method)
