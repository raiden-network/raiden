import pathlib

from installer.utils import (
    create_symlink,
    create_desktop_icon,
    download_file,
    extract_file,
)


def download_raiden_binary(target_path: pathlib.Path) -> pathlib.Path:
    """Download the latest Raiden client binary.

    TODO: This is a stub.
    """
    path = download_file(target_path, "version_string")
    return path


def install_raiden_binary(
    archive_path: pathlib.Path,
    target_path: pathlib.Path
) -> pathlib.Path:
    """Install the Raiden binary on this machine, unpacking the archive if necessary.

    TODO: This is a stub.
    """
    return target_path


def configure_raiden_client(bin_path: pathlib.Path, network: str) -> None:
    """configure the raiden client to use the given `network`.

    TODO: This is a stub.
    """


def show_safe_usage_requirements() -> None:
    """Print safe usage requirements to console.

    TODO: This is a stub.
    """
    print("Always wear a helmet when hacking on raiden!")


def install_raiden(download_cache_dir, binary_dir):
    # Download the binary
    archive_dir = download_raiden_binary(download_cache_dir)

    # Extract the archive
    bin_path = extract_archive(archive_dir, binary_dir)

    # Determine whether or not we should create a symbolic link and desktop icon
    # for the raiden client.

    # Copy binary to given directory, optionally adding a symbolic link.
    install_raiden_binary(bin_path)

    # TODO: User input require input validation.
    symbolic_link = input("Add a symbolic link to /usr/local/bin for Raiden? [Y/n]")
    if symbolic_link:
        create_symlink(bin_path)

    # TODO: User input require input validation.
    desktop_icon = input('Would you like to create a desktop icon for the Raiden client?')
    if desktop_icon:
        create_desktop_icon(bin_path)

    # Configure Raiden
    # TODO: User input require input validation.
    print(
        "\nPlease choose a Network to connect to:"
        "   [1] Test Network"
        "   [2] Main Network\n",
    )
    network = input("Your selection: [1]")
    configure_raiden_client(bin_path, network)

    # Display the requirements for safe usage and have the user confirm he read them.
    show_safe_usage_requirements()
