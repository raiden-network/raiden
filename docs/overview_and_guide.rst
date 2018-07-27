System Requirements and Installation Guide
##################################################
.. toctree::
  :maxdepth: 2

Introduction
============
Raiden is a payment channel implementation which provides scalable, low latency, and cheap token transfers for Ethereum.

.. _binary_releases:

Installation
============

.. warning:: If you are just switching from an old installation of raiden which was using python 2, then you should make sure to remove your raiden directory. By default that would mean: :code:`rm -rf ~/.raiden`

The preferred way to install Raiden is downloading a self contained application bundle from the
`GitHub release page <https://github.com/raiden-network/raiden/releases>`_.

Linux
*****

Download the latest :code:`raiden-<version>-linux.tar.gz`, and extract it::

    tar -xvzf raiden-<version>-linux.tar.gz

The Raiden binary should work on most 64bit GNU/Linux distributions without any specific system dependencies, other
than an Ethereum client installed in your system (see below). The Raiden binary takes the same command line
arguments as the ``raiden`` script.

macOS
*****

Download the latest :code:`raiden-<version>-macOS.zip`, and extract it::

    unzip raiden-<version>-macOS.zip

The resulting binary will work on any version of macOS from 10.12 onwards without any other
dependencies.

Or you can use Homebrew to install the most up to date binary::

    brew tap raiden-network/raiden
    brew install raiden

An Ethereum client is required in both cases. The Raiden binary takes the same command line
arguments as the ``raiden`` script.


Dependencies
************
You will need to have an Ethereum client installed in your system.

- Check `this link <https://github.com/ethereum/go-ethereum/wiki/Building-Ethereum>`_ for instructions on the go-ethereum client.
- Follow `these instructions <https://github.com/paritytech/parity#simple-one-line-installer-for-mac-and-ubuntu>`_ for  the parity client.

Now you are ready :ref:`to get started <running_raiden>`.

.. _installation:

For developers
==============
If you plan to develop on the Raiden source code, or the binary distributions do not work for your
system, you can follow these steps to install a development version.


Linux
*****

Additional dependencies for development installations
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- You need to make sure that your system has ``solc``, the ethereum solidity compiler installed. Refer to `its documentation`_ for the installation steps.
- You will also need to obtain the `system dependencies for pyethapp <https://github.com/ethereum/pyethapp/#installation-on-ubuntudebian>`_.

.. _its documentation: http://solidity.readthedocs.io/en/latest/installing-solidity.html

Installation from source
~~~~~~~~~~~~~~~~~~~~~~~~

Clone the repository::

    git clone https://github.com/raiden-network/raiden.git


Navigate to the directory::

    cd raiden

It's advised to create a `virtualenv <http://docs.python-guide.org/en/latest/dev/virtualenvs/>`_ for Raiden and install all python dependencies there.

After you have done that you can proceed to install the dependencies::

    pip install --upgrade -r requirements-dev.txt
    python setup.py develop

You will also need to connect your Ethereum client to the Ropsten testnet. See below for guidelines on how to connect with both Parity and Geth.


macOS
*****

Please refer to the :ref:`detailed step-by-step guide <macos_development_setup>` for setting up a macOS development environment.


.. _running_raiden:


Requirements for Safe Usage
===========================

In order to use Raiden correctly and safely there are some things that need to be taken care of by the user:

- **Layer 1 works reliably**: That means that you have a local ethereum node, either geth or parity, that is always synced and working reliably. If there are any problems or bugs on the client then Raiden can not work reliably.
- **Unique account for Raiden**: We need to have a specific ethereum account dedicated to Raiden. Creating any manual transaction with the account that Raiden uses, while the Raiden client is running, can result in undefined behaviour
- **Raiden account has sufficient ETH**: Raiden will try to warn you if there is not enough ETH in your raiden account in order to maintain your current open chanels and go through their entire cycle. But it is your job as the user to refill your account with ETH and always have it filled.
- **Persistency of local DB**: Your local state database is located at ``~/.raiden``. This data should not be deleted by the user or tampered with in any way. Frequent backups are also recommended. Deleting this directory could mean losing funds.
- **Raiden Always online**: Make sure that your node is always working, your network connection is stable and that the Raiden node is always online. If it crashes for whatever reason you are responsible to restart it and keep it always online. We recommend running it inside some form of monitor that will restart if for some reason the raiden node crashes.
- **Ethereum Client Always Online**: Make sure that your ethereum client is always running and is synced. We recommend running it inside some form of monitor that will restart if for some reason it crashes.


Firing it up
=============


Using geth
**********

Run the Ethereum client and let it sync with the Ropsten testnet::

    geth --testnet --fast --rpc --rpcapi eth,net,web3 --bootnodes "enode://20c9ad97c081d63397d7b685a412227a40e23c8bdc6688c6f37e97cfbc22d2b4d1db1510d8f61e6a8866ad7f0e17c02b14182d37ea7c3c8b9c2683aeb6b733a1@52.169.14.227:30303,enode://6ce05930c72abc632c58e2e4324f7c7ea478cec0ed4fa2528982cf34483094e9cbc9216e7aa349691242576d552a2a56aaeae426c5303ded677ce455ba1acd9d@13.84.180.240:30303"

Unless you already have an account you can also create one in the console by invoking ``personal.newAccount()``.

If problems arise for above method, please see `the Ropsten README <https://github.com/ethereum/ropsten>`_ for further instructions.

Then launch Raiden with the default testnet keystore path::

    raiden --keystore-path  ~/.ethereum/testnet/keystore

Using parity
************

Run the client and let it sync with the Ropsten testnet::

    parity --chain ropsten --bootnodes "enode://20c9ad97c081d63397d7b685a412227a40e23c8bdc6688c6f37e97cfbc22d2b4d1db1510d8f61e6a8866ad7f0e17c02b14182d37ea7c3c8b9c2683aeb6b733a1@52.169.14.227:30303,enode://6ce05930c72abc632c58e2e4324f7c7ea478cec0ed4fa2528982cf34483094e9cbc9216e7aa349691242576d552a2a56aaeae426c5303ded677ce455ba1acd9d@13.84.180.240:30303"

After syncing the chain, an existing Ethereum account can be used or a new one can be generated using ``parity-ethkey``.
After account creation, launch Raiden with the path of your keystore supplied::

    raiden --keystore-path ~/.local/share/io.parity.ethereum/keys/test

Select the desired Ethereum account when prompted, and type in the account's password.


See the :doc:`API walkthrough <api_walkthrough>` for further instructions on how to interact with Raiden.
