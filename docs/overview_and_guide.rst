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
The preferred way to install Raiden is downloading a self contained application bundle from the `GitHub release page <https://github.com/raiden-network/raiden/releases>`_. Download the latest ``raiden--x86_64.AppImage``, and make it executable::

    chmod +x raiden--x86_64.AppImage

The Raiden `AppImage <http://appimage.org/>`_ should work on most 64bit GNU/Linux distributions without any specific system dependencies, other than an Ethereum client installed in your system (see below). The Raiden AppImage bundle takes the same command line arguments as the ``raiden`` script.  

Dependencies
************
You will need to have an Ethereum client installed in your system.

- Check `this link <https://github.com/ethereum/go-ethereum/wiki/Building-Ethereum>`_ for instructions on the go-ethereum client.
- Follow `these instructions <https://github.com/paritytech/parity#simple-one-line-installer-for-mac-and-ubuntu>`_ for  the parity client.

Now you are ready :ref:`to get started <running_raiden>`. 

.. _installation:

For developers
==============
If you plan to develop on the Raiden source code, or the AppImage install does not work for your system, you can follow these steps to install a development version.

Additional dependencies for development installations
*****************************************************
- You need to make sure that your system has ``solc``, the ethereum solidity compiler installed. Refer to `its documentation <http://solidity.readthedocs.io/en/latest/installing-solidity.html>`_ for the installation steps.
- You will also need to obtain the `system dependencies for pyethapp <https://github.com/ethereum/pyethapp/#installation-on-ubuntudebian>`_.

Installation from source
************************

Clone the repository::

    git clone https://github.com/raiden-network/raiden.git


Navigate to the directory::

    cd raiden

It's advised to create a `virtualenv <http://docs.python-guide.org/en/latest/dev/virtualenvs/>`_ for Raiden and install all python dependencies there.

After you have done that you can proceed to install the dependencies::

    pip install --upgrade -r requirements.txt
    python setup.py develop

You will also need to connect your Ethereum client to the Ropsten testnet. See below for guidelines on how to connect with both Parity and Geth.


.. _running_raiden:

Firing it up
=============

Using geth
**********

Run the Ethereum client and let it sync with the Ropsten testnet::

    geth --testnet --fast --rpc --rpcapi eth,net,web3,debug --bootnodes "enode://20c9ad97c081d63397d7b685a412227a40e23c8bdc6688c6f37e97cfbc22d2b4d1db1510d8f61e6a8866ad7f0e17c02b14182d37ea7c3c8b9c2683aeb6b733a1@52.169.14.227:30303,enode://6ce05930c72abc632c58e2e4324f7c7ea478cec0ed4fa2528982cf34483094e9cbc9216e7aa349691242576d552a2a56aaeae426c5303ded677ce455ba1acd9d@13.84.180.240:30303"

Unless you already have an account you can also create one in the console by invoking ``personal.newAccount()``.

If problems arise for above method, please see `the Ropsten README <https://github.com/ethereum/ropsten>`_ for further instructions.

Then launch Raiden with the default testnet keystore path::

    raiden --keystore-path  ~/.ethereum/testnet/keystore

Using parity
************

Run the client and let it sync with the Ropsten testnet::

    parity --chain ropsten --bootnodes "enode://20c9ad97c081d63397d7b685a412227a40e23c8bdc6688c6f37e97cfbc22d2b4d1db1510d8f61e6a8866ad7f0e17c02b14182d37ea7c3c8b9c2683aeb6b733a1@52.169.14.227:30303,enode://6ce05930c72abc632c58e2e4324f7c7ea478cec0ed4fa2528982cf34483094e9cbc9216e7aa349691242576d552a2a56aaeae426c5303ded677ce455ba1acd9d@13.84.180.240:30303"

After syncing the chain, create an account on the Ropsten testnet by navigating to the url that parity shows.  It is usually::

    http://127.0.0.1:8180

After account creation, launch Raiden with the path of your keystore supplied::

    raiden --keystore-path ~/.local/share/io.parity.ethereum/keys/test"

Select the Ethereum account when prompted, and type in the account's password.


See the :doc:`API walkthrough <api_walkthrough>` for further instructions on how to interact with Raiden.
