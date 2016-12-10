# Raiden Network

[![Gitter](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/brainbot-com/raiden?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)

Raiden Network is a proposed extension to Ethereum which scales-out asset transfer capacity.

It's inspired by the Lightning Network which leverages off-chain asset transfers to carry out the vast majority of transactions.

This is work in progress.

## Installation

Please follow the [installation instructions in the wiki](https://github.com/raiden-network/raiden/wiki/Raiden-PoC%E2%80%900#system-dependencies).

### macOS specifics
First install the system-dependecies for a successful build of the Python packages:

1. `brew install pkg-config libffi automake`
2. `export PKG_CONFIG_PATH=/usr/local/Cellar/libffi/3.0.13/lib/pkgconfig/`


### Ropsten testnet

These are the currently deployed contract addresses for the Ropsten Testnet:

Netting Channel Library: [0x5208baa313256c0e703c96b06c896875b823cc11](https://testnet.etherscan.io/address/0x5208baa313256c0e703c96b06c896875b823cc11)
Channel Manager Library: [0x196da534e3860398f2d9c27cb93fb4bac69715eb](https://testnet.etherscan.io/address/0x196da534e3860398f2d9c27cb93fb4bac69715eb)
Registry Contract: [0x32c5dab9b099a5b6c0e626c1862c07b30f58d76a](https://testnet.etherscan.io/address/0x32c5dab9b099a5b6c0e626c1862c07b30f58d76a)
Discovery Contract: [0x79ab17cc105e820368e695dfa547604651d02cbb](https://testnet.etherscan.io/address/0x79ab17cc105e820368e695dfa547604651d02cbb)

### Versions and releases

Currently we aim to create proof of concept releases weekly, not based on a certain
feature level. All proof of concept releases will have version numbers in the
`0.0.x` range (so `PoC-1` = `0.0.1`).

#### Developer notice:

To create a proof of concept release, install [`bumpversion`](https://github.com/peritus/bumpversion), update your
`master` branch to the latest upstream version (i.e. `git checkout master && git pull --rebase`), then call

```
prepare_poc_release.sh
```

This will bump the version and create a commit on a new branch `poc_release_{version}`,
which will be pushed to the upstream repository and create a PR.

From there, follow the steps from the script (i.e. merge PR and tag the result
on the master branch, which will trigger the pypi release.
