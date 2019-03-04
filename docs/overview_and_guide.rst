System Requirements and Installation Guide
##################################################
.. toctree::
  :maxdepth: 2

Introduction
============
Raiden is a payment channel implementation which provides scalable, low latency, and cheap token payments for Ethereum.

.. _binary_releases:

Installation
============

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

Raspberry Pi
************

Download the latest :code:`raiden-<version>-linux-armv7l.tar.gz` for the Raspberry Pi Model 2B or
download the latest :code:`raiden-<version>-linux-aarch64.tar.gz` for the Raspberry Pi Model 2B v 1.2 or later,
and extract it::

    tar -xvzf  raiden-<version>-linux-*.tar.gz

The resulting binary will work on any Raspberry Pi from Model 2B onwards without any other
dependencies.

An Ethereum client is required in both cases. The Raiden binary takes the same command line
arguments as the ``raiden`` script.


Docker
******

There are two options to run a raiden docker image:

Create the Image yourself and use our `Dockerfile <https://github.com/raiden-network/raiden/blob/master/docker/Dockerfile>`_ as template or use the already built image from Dockerhub::

      docker run -it raidennetwork/raiden:latest

The required keystore can easily be mounted in the docker container::

      docker run -it --mount src=/PATH/TO/LOCAL/KEYSTORE,target=/keystore,type=bind raidennetwork/raiden:latest --keystore-path /keystore

Other flags such as the JSON-RPC endpoint to an Ethereum node can easily be chained to the command.


Dependencies
************
You will need to have an Ethereum client installed in your system. Alternatively, you can skip
the setup of an ethereum node and use the :ref:`--eth-rpc-endpoint <using_rpc-endpoint>` argument to remotely use an ethereum node of your choice.

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

.. _installation_from_source:

Installation from source
~~~~~~~~~~~~~~~~~~~~~~~~

Clone the repository::

    git clone https://github.com/raiden-network/raiden.git


Navigate to the directory::

    cd raiden

It's advised to create a `virtualenv <http://docs.python-guide.org/en/latest/dev/virtualenvs/>`_ for Raiden (requires python3.7) and install all python dependencies there.

After you have done that you can proceed to install the dependencies::

    pip install -c constraints.txt --upgrade -r requirements-dev.txt
    python setup.py develop

You will also need to connect your Ethereum client to the Ropsten testnet. See below for guidelines on how to connect with both Parity and Geth.


macOS
*****

Please refer to the :ref:`detailed step-by-step guide <macos_development_setup>` for setting up a macOS development environment.

nix
***

Please refer to the :ref:`nix setup guide <nix_development_setup>` for setting up a development environment using the `nix <https://nixos.org/nix>`_ package manager.


.. _running_raiden:


Requirements for Safe Usage
===========================

In order to use Raiden correctly and safely there are some things that need to be taken care of by the user:

- **Layer 1 works reliably**: That means that you have a local Ethereum node, either geth or parity, that is always synced and working reliably. If there are any problems or bugs on the client then Raiden can not work reliably.
- **Unique account for Raiden**: We need to have a specific Ethereum account dedicated to Raiden. Creating any manual transaction with the account that Raiden uses, while the Raiden client is running, can result in undefined behaviour
- **Raiden account has sufficient ETH**: Raiden will try to warn you if there is not enough ETH in your Raiden account in order to maintain your current open channels and go through their entire cycle. But it is your job as the user to refill your account with ETH and always have it filled.
- **Persistency of local DB**: Your local state database is located at ``~/.raiden``. This data should not be deleted by the user or tampered with in any way. Frequent backups are also recommended. Deleting this directory could mean losing funds.
- **Raiden Always online**: Make sure that your node is always working, your network connection is stable and that the Raiden node is always online. If it crashes for whatever reason you are responsible to restart it and keep it always online. We recommend running it inside some form of monitor that will restart if for some reason the Raiden node crashes.
- **Ethereum Client Always Online**: Make sure that your Ethereum client is always running and is synced. We recommend running it inside some form of monitor that will restart if for some reason it crashes.
- **Ethereum Client can not be changed**: Swapping the Ethereum client while transactions are not mined is considered unsafe. We recommend avoiding switching Ethereum clients once the Raiden node is running.
- **Never expose the Raiden REST API to the public**: For Raiden's operation, the client needs to be able to sign transactions at any point in time. Therefore you should never expose the Raiden Rest API to the public. Be very careful when changing the --rpc and --rpccorsdomain values.
- **Be patient**: Do not mash buttons in the webUI and do not shut down the client while on-chain transactions are on the fly and have not yet been confirmed.

Firing it up
=============


Using geth
**********

Run the Ethereum client and let it sync::

    geth --syncmode fast --rpc --rpcapi eth,net,web3,txpool

.. note::
    When you want to use a testnet add the ``--testnet`` or ``--rinkeby`` flags or set the network id with ``--networkid`` directly.

Unless you already have an account you can also create one in the console by invoking ``personal.newAccount()``.

If problems arise for above method, please see `the Ropsten README <https://github.com/ethereum/ropsten>`_ for further instructions.

Then launch Raiden with the default testnet keystore path::

    raiden --keystore-path  ~/.ethereum/testnet/keystore

Using parity
************

Run the client and let it sync::

    parity --no-warp --jsonrpc-apis=web3,eth,net,parity

.. note::
    When you want to use a testnet add the ``--chain ropsten`` or ``--chain kovan`` flags or set the network id with ``--network-id`` directly.

.. attention:: Parity sometimes loses its historical DB (potentially after updates). Due to this some events might be lost which will result in Raiden not being able to fetch all events. Therefore it is recommended to make sure to have Parity fully synced with the `--no-warp` option.

After syncing the chain, an existing Ethereum account can be used or a new one can be generated using ``parity-ethkey``.
After account creation, launch Raiden with the path of your keystore supplied::

    raiden --keystore-path ~/.local/share/io.parity.ethereum/keys/test

.. _using_rpc-endpoint:

Using --eth-rpc-endpoint/Infura
*******************************

.. warning::
    Raiden may fail during restarts when Infura is used. This can happen because Raiden does not know about transactions in the memory pool and therefore new transactions might reuse these nonces. This will lead to a node crash.

In order to use Raiden with an rpc-endpoint provided by an Infura Ethereum node, sign up with `Infura <https://infura.io/>`_ to get an API token. After that you can start using Raiden on Ropsten directly::

    raiden --keystore-path  ~/.ethereum/testnet/keystore --eth-rpc-endpoint "https://mainnet.infura.io/v3/<yourToken>"

.. note::
    When you want to use a testnet you need to update the URL of the infura endpoints, e.g. for the ropsten testnet use ``https://ropsten.infura.io/v3/<yourToken>``

Select the desired Ethereum account when prompted, and type in the account's password.


See the :doc:`API walkthrough <api_walkthrough>` for further instructions on how to interact with Raiden.
