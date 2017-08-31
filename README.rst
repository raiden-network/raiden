Raiden Network
==============

.. image:: https://badges.gitter.im/Join%20Chat.svg
    :target: https://gitter.im/raiden-network/raiden?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge
    :alt: Chat on Gitter

`Raiden Network documentation`_

.. _Raiden Network documentation: http://raiden-network.readthedocs.io/

Raiden is a proposed extension to Ethereum which scales-out asset transfer capacity in the network.
It is inspired by the `Lightning Network`_ which leverages off-chain asset transfers to carry out the vast majority of transactions.
For more information please visit http://raiden.network/.

.. _Lightning Network: https://lightning.network/

**Note:** *This is work in progress*

Installation
------------

Please refer to the `Installation`_ section in the official docs.

.. _Installation: http://raiden-network.readthedocs.io/en/stable/overview_and_guide.html#installation

macOS specifics
~~~~~~~~~~~~~~~

First install the system-dependencies for a successful build of the Python packages::

    brew install pkg-config libffi automake

Then set the environment variable for your `pkg-config` path to `libffi`::

    export PKG_CONFIG_PATH=/usr/local/Cellar/libffi/3.0.13/lib/pkgconfig/


Ropsten testnet
~~~~~~~~~~~~~~~

These are the currently deployed contract addresses for the Ropsten testnet:

* Netting Channel Library: 0x5208baa313256c0e703c96b06c896875b823cc11_
* Channel Manager Library: 0x196da534e3860398f2d9c27cb93fb4bac69715eb_
* Registry Contract: 0x32c5dab9b099a5b6c0e626c1862c07b30f58d76a_
* Discovery Contract: 0x79ab17cc105e820368e695dfa547604651d02cbb_

.. _0x5208baa313256c0e703c96b06c896875b823cc11: https://ropsten.etherscan.io/address/0x5208baa313256c0e703c96b06c896875b823cc11
.. _0x196da534e3860398f2d9c27cb93fb4bac69715eb: https://ropsten.etherscan.io/address/0x196da534e3860398f2d9c27cb93fb4bac69715eb
.. _0x32c5dab9b099a5b6c0e626c1862c07b30f58d76a: https://ropsten.etherscan.io/address/0x32c5dab9b099a5b6c0e626c1862c07b30f58d76a)
.. _0x79ab17cc105e820368e695dfa547604651d02cbb: https://ropsten.etherscan.io/address/0x79ab17cc105e820368e695dfa547604651d02cbb)

Versions and releases
~~~~~~~~~~~~~~~~~~~~~

Currently we aim to create proof of concept releases weekly, not based on a certain
feature level. All proof of concept releases will have version numbers in the
`0.0.x` range (so `PoC-1` = `0.0.1`).

Create a PoC release
++++++++++++++++++++

Install bumpversion_

.. _bumpversion: https://github.com/peritus/bumpversion

Update your `master` branch to the latest upstream version::

    git checkout master && git pull --rebase

Call the release script::

    prepare_poc_release.sh

This will bump the version, create a commit on a new branch `poc_release_{version}`, push this branch to the upstream repository and create a PR.

Follow the steps from the script to merge the PR and tag the result on the master branch, which will trigger the [PyPI](https://pypi.python.org) release.
