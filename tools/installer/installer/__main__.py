"""One-click installer application."""
import pathlib

from installer.steps import (
    install_raiden,
    install_eth_client,
    account_setup,
    fund_account,
    token_acquisition,
)
# TODO: User input require input validation.
# Choose a default installation directory
tar_dir = input("Choose a installation directory: [/opt/raiden]") or "/opt/raiden"
install_root_path = pathlib.Path(tar_dir)

# Create directories for installing.
install_root_path.mkdir(exist_ok=True, parents=True)
download_cache_dir = install_root_path.joinpath('cache')
binary_dir = install_root_path.joinpath('bin')

################################################################################
# Install the Raiden Client
################################################################################

install_raiden(download_cache_dir, binary_dir)

################################################################################
# Install Ethereum Client
################################################################################

install_eth_client(download_cache_dir, binary_dir)

################################################################################
# Setup Account for Raiden Development
################################################################################

account_setup()

################################################################################
# Fund accounts with Ether
################################################################################

fund_account()

################################################################################
# Acquire Tokens
################################################################################
token_acquisition()
