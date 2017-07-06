# Raiden

[![Gitter](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/raiden-network/raiden?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)

Raiden is a proposed extension to Ethereum which scales-out asset transfer capacity in the network. It is inspired by the [Lightning Network](https://lightning.network/) which leverages off-chain asset transfers to carry out the vast majority of transactions. For more information please visit http://raiden.network/.

**Note:** *This is work in progress*

## Installation

You can find the installation instructions of [Raiden PoC-0](https://github.com/raiden-network/raiden/wiki/Raiden-PoC%E2%80%900#getting-started-with-raiden) on the wiki, but for the latest releases, make sure you are using the Ropsten testnet instead.

### macOS specifics
First install the system-dependecies for a successful build of the Python packages
```
brew install pkg-config libffi automake
```
Then set the environment variable for your `pkg-config` path to `libffi`
```
export PKG_CONFIG_PATH=/usr/local/Cellar/libffi/3.0.13/lib/pkgconfig/
```

### Ropsten testnet

These are the currently deployed contract addresses for the Ropsten testnet:

* Netting Channel Library: [0x5208baa313256c0e703c96b06c896875b823cc11](https://ropsten.etherscan.io/address/0x5208baa313256c0e703c96b06c896875b823cc11)
* Channel Manager Library: [0x196da534e3860398f2d9c27cb93fb4bac69715eb](https://ropsten.etherscan.io/address/0x196da534e3860398f2d9c27cb93fb4bac69715eb)
* Registry Contract: [0x32c5dab9b099a5b6c0e626c1862c07b30f58d76a](https://ropsten.etherscan.io/address/0x32c5dab9b099a5b6c0e626c1862c07b30f58d76a)
* Discovery Contract: [0x79ab17cc105e820368e695dfa547604651d02cbb](https://ropsten.etherscan.io/address/0x79ab17cc105e820368e695dfa547604651d02cbb)

### Versions and releases

Currently we aim to create proof of concept releases weekly, not based on a certain
feature level. All proof of concept releases will have version numbers in the
`0.0.x` range (so `PoC-1` = `0.0.1`).

#### Create a PoC release

Install `bumpversion` (see https://github.com/peritus/bumpversion)

Update your `master` branch to the latest upstream version
```
git checkout master && git pull --rebase
```
Call the release script
```
prepare_poc_release.sh
```
This will bump the version, create a commit on a new branch `poc_release_{version}`, push this branch to the upstream repository and create a PR.

Follow the steps from the script to merge the PR and tag the result on the master branch, which will trigger the [PyPI](https://pypi.python.org) release.
