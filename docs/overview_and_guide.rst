System Requirements and Installation Guide
##########################################
.. toctree::
  :maxdepth: 2

Introduction
============
Raiden is a payment channel implementation which provides scalable, low latency, and cheap token payments for Ethereum.

.. _binary_releases:

Installation
============

To install Raiden you can either:

    * Use the Raiden Wizard
    * Download a self contained application bundle from the `GitHub release page <https://github.com/raiden-network/raiden/releases>`_
    * Use pip or, on macOS, homebrew
    * Run a raiden docker image

Below we will give details on how to use the self contained application bundles on different platforms, as well as the other installation methods.

Installation via Raiden Wizard
******************************

If you are new to Raiden or just want to use it without caring too much for the technical details, we recommend the Raiden Wizard to get started.

.. toctree::
  :maxdepth: 2

  installation/quick-start/README

Installation from GitHub
************************

Linux
~~~~~

`Download <https://github.com/raiden-network/raiden/releases>`_ the latest :code:`raiden-<version>-linux-x86_64.tar.gz`, and extract it::

    tar -xvzf raiden-<version>-linux-x86_64.tar.gz

The Raiden binary should work on most 64bit GNU/Linux distributions without any specific system dependencies, other
than an Ethereum client installed in your system (see below). The Raiden binary takes the same command line
arguments as the ``raiden`` script.

macOS
~~~~~

`Download <https://github.com/raiden-network/raiden/releases>`_ the latest :code:`raiden-<version>-macOS-x86_64.zip`, and extract it::

    unzip raiden-<version>-macOS-x86_64.zip

The resulting binary will work on any version of macOS from 10.12 onwards without any other
dependencies.

Or you can use Homebrew to install the most up to date binary::

    brew tap raiden-network/raiden
    brew install raiden

An Ethereum client is required in both cases. The Raiden binary takes the same command line
arguments as the ``raiden`` script.

Raiden is also available as a PyPi package and can be installed with ``pip install raiden``.

Raspberry Pi
~~~~~~~~~~~~

`Download <https://github.com/raiden-network/raiden/releases>`_ the latest :code:`raiden-<version>-linux-armv7l.tar.gz` or :code:`raiden-<version>-linux-aarch64.tar.gz` for the respective Raspberry Pi Model and extract it::

    tar -xvzf  raiden-<version>-linux-*.tar.gz

The resulting binary will work on any Raspberry Pi from Model 2B onwards without any other
dependencies.

An Ethereum client is required in both cases. The Raiden binary takes the same command line
arguments as the ``raiden`` script.


Installation using pip
**********************

To get the latest available stable version via `pip`::

    pip install raiden

If you'd like to give the pre-releases a spin, use pip's `--pre` flag::

    pip install --pre raiden

Installation via Docker
***********************

There are two options to run a raiden docker image:

Create the Image yourself and use our `Dockerfile <https://github.com/raiden-network/raiden/blob/master/docker/Dockerfile>`_ as template or use the already built image from Dockerhub::

      docker run -it raidennetwork/raiden:latest

The required keystore can easily be mounted in the docker container::

      docker run -it --mount src=/PATH/TO/LOCAL/KEYSTORE,target=/keystore,type=bind raidennetwork/raiden:latest --keystore-path /keystore

Other flags such as the JSON-RPC endpoint to an Ethereum node can easily be chained to the command.


Dependencies
************
You will need a local or remote Ethereum node to connect Raiden to.

- Check `this link <https://github.com/ethereum/go-ethereum/wiki/Building-Ethereum>`_ to install the go-ethereum client.
- Follow `these instructions <https://github.com/paritytech/parity#simple-one-line-installer-for-mac-and-ubuntu>`_ to install the parity client.
- Or sign up at a service like `Infura <https://infura.io>`_ to set up a remote node.

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

It's strongly advised to create a virtualenv_ for Raiden (requires python3.7) and install all python dependencies there.

After you have done that you can proceed to install the dependencies::

    make install-dev

You will also need to connect your Ethereum client to the Ropsten testnet. See below for guidelines on how to connect with both Parity and Geth.

.. _virtualenv: https://docs.python.org/3/library/venv.html

macOS
*****

Please refer to the :ref:`detailed step-by-step guide <macos_development_setup>` for setting up a macOS development environment.

nix
***

Please refer to the :ref:`nix setup guide <nix_development_setup>` for setting up a development environment using the `nix <https://nixos.org/nix>`_ package manager.


.. _running_raiden:


Firing it up
=============

To fire up Raiden you need at least
 1. a synced **Ethereum Node** - using geth, parity or infura
 2. an **Ethereum keystore file** - whereas the address holds ETH, RDN, and the ERC20 token you want to transfer
 3. If you want to use :doc:`Raiden services <raiden_services>` that charge a fee, a deposit of RDN tokens to pay the services with.

More about the Raiden services (pathfinding and monitoring service) will be explained below. On the testnets there are also free services available, and on any network it is possible (though not recommended) to use Raiden without Raiden services.

We will provide you with the necessary cli arguments step by step. Full example is at the end of the page.

1. and 2. The synced Ethereum Node & Keystore
*********************************************

- **Using geth**

Run the Ethereum client and let it sync::

    geth --syncmode fast --rpc --rpcapi eth,net,web3

.. note::
    When you want to use a testnet add one of the ``--testnet``, ``--rinkeby`` or ``--goerli`` flags or set the network id with ``--network-id`` directly.

Unless you already have an account you can also create one in the console by invoking ``personal.newAccount()``.

If problems arise for above method, please see `the Ropsten README <https://github.com/ethereum/ropsten>`_ for further instructions.

Then launch Raiden with the default testnet keystore path::

    raiden --keystore-path  ~/.ethereum/testnet/keystore --pathfinding-service-address $PFS_ADDRESS

- **Using parity**

Run the client and let it sync::

    parity --no-warp --jsonrpc-apis=web3,eth,net,parity

.. note::
    When you want to use a testnet add the ``--chain ropsten`` or ``--chain kovan`` flags or set the network id with ``--network-id`` directly.

.. attention:: Parity sometimes loses its historical DB (potentially after updates). Due to this some events might be lost which will result in Raiden not being able to fetch all events. Therefore it is recommended to make sure to have Parity fully synced with the ``--no-warp`` option.

After syncing the chain, an existing Ethereum account can be used or a new one can be generated using ``parity-ethkey``.
After account creation, launch Raiden with the path of your keystore supplied::

    raiden --keystore-path ~/.local/share/io.parity.ethereum/keys/test --pathfinding-service-address $PFS_ADDRESS

.. _using_rpc-endpoint:

- **Using Infura**

Sign up with `Infura <https://infura.io/>`_ to get an API token. After that you can start using Raiden directly::

    raiden --keystore-path  ~/.ethereum/testnet/keystore --eth-rpc-endpoint "https://<network>.infura.io/v3/<yourToken>"

Where `<network>` can be mainnet, ropsten, etc.

Select the desired Ethereum account when prompted, and type in the account's password.

3. Depositing tokens to pay the services
****************************************

To pay the services, you have to lock some of your Raiden tokens in the ``UserDeposit`` contract.
Normally the Raiden Wizard or some other auxilliary scripts would do the contract interaction for you.
In this section, we will briefly explain how it can be done manually so you are able to use Raiden without them.

All services that are registered in the service registry of a given network will use one shared instance of ``UserDeposit``.
You can obtain the address of the contract from

    ``https://github.com/raiden-network/raiden-contracts/blob/master/raiden_contracts/data/deployment_services_<network>.json``

where ``network`` is one of ``mainnet``, ``ropsten``, ``rinkeby`` or ``goerli``.

As an example, suppose we want to run a Raiden node with address ``0x3040435D7F1012e861f0B0989422a47D1825F120`` on the mainnet
and deposit 10 Raiden tokens (10**19 REI) for it to use. Here we use `MetaMask <https://metamask.io>`_ to access our wallet
and the contract interface of `Etherscan <https://etherscan.io>`_ to do the transactions. Of course, you can also use another
service or your own Ethereum node.

We log into MetaMask with our account that holds the Raiden tokens (which should be a different account than the one we use with
Raiden, as the latter is supposed to be used with Raiden only.) To find the ``UserDeposit`` contract, we take a look at ``deployment_services_mainnet.json``:

.. code-block:: none

    {
        "contracts_version": null, "chain_id": 1,
        (...)
        "UserDeposit": {
            "address": "0x53Cc1decDD7d452c8844a5f383e23AD479A1f614",
            (...)


We can then look up the contract address on Etherscan, and use Etherscan's "read/write contract" panels to interact with it.
The Raiden token (RDN) can be searched by name on Etherscan, or we can look up its address in the ``UserDeposit`` contract's
``token`` property. On the testnets, the token symbol is SVT (service token) rather than RDN and it may not be possible
to find the token by name, but it can always be found in ``UserDeposit.token``.


As usual with ERC-20 tokens, we need to call two contract functions:

.. code-block:: none

    approve(0x53Cc1decDD7d452c8844a5f383e23AD479A1f614, 10000000000000000000)

on the RDN (or SVT) token contract, to allow the ``UserDeposit`` contract to move the 10 RDN, and

.. code-block:: none

    deposit(0x3040435D7F1012e861f0B0989422a47D1825F120, 10000000000000000000)

on the ``UserDeposit`` contract.


Optional CLI arguments
======================

There are further CLI arguments with which you can control, among other things

 1. The choice of a pathfinding service
 2. The choice of a monitoring service
 3. Logging

1. Pathfinding service
**********************

A pathfinding service is a third party service helping your node with efficient transfer routing. It is usually paid in RDN tokens.

Direct channels to other nodes can be used without asking the PFS for a route.
If you want to stop broadcasting information about your channel states to
PFSes, use ``--routing-mode private``. As a result, PFSes won't create routes
that include your node as a mediator.

If you want to use a particular pathfinding service, e.g. one of the testnet pathfinding services given below, you can
do so with ``--pathfinding-service-address <url>``. Otherwise Raiden will automatically pick one of the pathfinding
services from the registry.

The default setting for the pathfinding options is to use a pathfinding service and choose it automatically
(``--routing-mode pfs --pathfinding-service-address auto``).

There are pathfinding services running on every testnet at the moment, some that charge fees and some that are for free.

+------------+----------------------------------------------------------+-------------------------------------------------+
| Testnet    | pfs with fees                                            | pfs without fees                                |
+============+==========================================================+=================================================+
| Görli      | https://pfs-goerli-with-fee.services-dev.raiden.network  | https://pfs-goerli.services-dev.raiden.network  |
+------------+----------------------------------------------------------+-------------------------------------------------+
| Ropsten    | https://pfs-ropsten-with-fee.services-dev.raiden.network | https://pfs-ropsten.services-dev.raiden.network |
+------------+----------------------------------------------------------+-------------------------------------------------+
| Kovan      | https://pfs-kovan-with-fee.services-dev.raiden.network   | https://pfs-kovan.services-dev.raiden.network   |
+------------+----------------------------------------------------------+-------------------------------------------------+
| Rinkeby    | https://pfs-rinkeby-with-fee.services-dev.raiden.network | https://pfs-rinkeby.services-dev.raiden.network |
+------------+----------------------------------------------------------+-------------------------------------------------+

For the mainnet we don't want to prefer and suggest specific pathfinding services.

2. Monitoring service
*********************

A monitoring service watches a client's open channels while it is offline, and represents the client in case of settlement.
Like the pathfinding service, it is paid in RDN tokens. If you want to use a monitoring service, use the option
``--enable-monitoring`` and Raiden will automatically pick one from its service registry.

3. Logging configuration
************************

By default raiden keeps a "debug" log file so that people who have not configured logging but are facing problems can still provide us with some logs to debug their problems.

For expert users of raiden who want to configure proper logging we recommend disabling the debug log file and configuring normal logging appropriately.

To disable the log file the ``--disable-debug-logfile`` argument should be passed.

To specify the logging level add: ``--log-config ":debug"`` if you want all debug statements to be logged. The logging level can actually be configured down to the module level through this argument.

To provide the filename for the logs use ``--log-file XXX`` where ``XXX`` is the full path and filename to the log you want to create or append to. Note that Raiden uses a python `WatchedFileHandler <https://docs.python.org/3/library/logging.handlers.html#watchedfilehandler>`__ for this log. That means that if you or your system moves the logfile (for example due to log rotation) then Raiden will detect that and close and reopen the log file handler with the same name.

Finally by default the output of the logs are in plain readable text format. In order to make them machine readable and parsable json add the ``--log-json`` argument.

Summing up these are the arguments you need to append if you want to disable the debug log and want to configure normal logging for up to debug statement in json inside a file called ``raiden.log``

``--disable-debug-logfile --log-config ":debug" --log-file raiden.log --log-json``
