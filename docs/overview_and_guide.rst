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

To install Raiden you can either:

    * Use the `Raiden Wizard <https://docs.raiden.network/quick-start/>`_
    * Download a self contained application bundle from the `GitHub release page <https://github.com/raiden-network/raiden/releases>`_

**If you're installing Raiden from the self contained application bundle the following sections will detail how to set up Raiden on various platforms.**

Linux
*****

Download the latest :code:`raiden-<version>-linux-x86_64.tar.gz`, and extract it::

    tar -xvzf raiden-<version>-linux-x86_64.tar.gz

The Raiden binary should work on most 64bit GNU/Linux distributions without any specific system dependencies, other
than an Ethereum client installed in your system (see below). The Raiden binary takes the same command line
arguments as the ``raiden`` script.

Raiden is also available as a PyPi package and can be installed with ``pip install raiden``.

macOS
*****

Download the latest :code:`raiden-<version>-macOS-x86_64.zip`, and extract it::

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
************

`Download <https://github.com/raiden-network/raiden/releases>`_ the latest :code:`raiden-<version>-linux-armv7l.tar.gz` or :code:`raiden-<version>-linux-aarch64.tar.gz` for the respective Raspberry Pi Model and extract it::

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
- **"Wormhole Attack" is possible** When your Raiden node plays the role of a mediator, so-called "wormhole attack" is possible. Under this attack, even though the whole payment succeeds, your incoming and outgoing capacities will be locked until the expiration, and the attackers gain mediation fees. However, such an attacker can also avoid your node altogether, and avoid locking their capacities.
- **Be patient**: Do not mash buttons in the webUI and do not shut down the client while on-chain transactions are on the fly and have not yet been confirmed.

Firing it up
=============

To fire up Raiden you need at least
 1. a synced **Ethereum Node** - using geth, parity or infura
 2. an **Ethereum keystore file** - whereas the address holds ETH, RDN, and the ERC20 token you want to transfer
 3. the address of your favorite **pathfinding service** - local routing is possible but no recommended

We will provide you with the necessary cli arguments step by step. Full example is at the end of the page.

1. and 2. The synced Ethereum Node & Keystore
*********************************************

- **Using geth**

Run the Ethereum client and let it sync::

    geth --syncmode fast --rpc --rpcapi eth,net,web3

.. note::
    When you want to use a testnet add the ``--testnet`` or ``--rinkeby`` flags or set the network id with ``--networkid`` directly.

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

.. warning::
    Raiden may fail during restarts when Infura is used. This can happen because Raiden does not know about transactions in the memory pool and therefore new transactions might reuse these nonces. This will lead to a node crash.

In order to use Raiden with an rpc-endpoint provided by an Infura Ethereum node, sign up with `Infura <https://infura.io/>`_ to get an API token. After that you can start using Raiden on Ropsten directly::

    raiden --keystore-path  ~/.ethereum/testnet/keystore --eth-rpc-endpoint "https://ropsten.infura.io/v3/<yourToken>" --pathfinding-service-address $PFS_ADDRESS

.. note::
    When you want to use a testnet you need to update the URL of the infura endpoints, e.g. for the ropsten testnet use ``https://ropsten.infura.io/v3/<yourToken>``

Select the desired Ethereum account when prompted, and type in the account's password.

3. The Pathfinding Address
***************************

Raiden provides a pathfinding service for efficient transfer routing. The default option when starting the client is with the pathfinding service to be paid in RDN tokens.

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

To start Raiden you need to provide a valid pathfinding service address, e.g. for Görli::

    raiden --keystore-path  ~/.ethereum/testnet/keystore --eth-rpc-endpoint "https://goerli.infura.io/v3/<yourToken>" --pathfinding-service-address "https://pfs-goerli.services-dev.raiden.network"


Now that Raiden is up and running, head over to the :doc:`API walkthrough <api_walkthrough>` for further instructions on how to interact with Raiden. There's also a :doc:`Web UI tutorial <webui_tutorial>` available for people who prefer a graphical interface.


Optional CLI arguments
***************************

In this section we will see how some optional CLI arguments work and what you can achieve by using them.

Logging configuration
~~~~~~~~~~~~~~~~~~~~~

By default raiden keeps a "debug" log file so that people who have not configured logging but are facing problems can still provide us with some logs to debug their problems.

For expert users of raiden who want to configure proper logging we recommend disabling the debug log file and configuring normal logging appropriately.

To disable the log file the ``--disable-debug-logfile`` argument should be passed.

To specify the logging level add: ``--log-config ":debug"`` if you want all debug statements to be logged. The logging level can actually be configured down to the module level through this argument.

To provide the filename for the logs use ``--log-file XXX`` where ``XXX`` is the full path and filename to the log you want to create or append to. Note that Raiden uses a python `WatchedFileHandler <https://docs.python.org/3/library/logging.handlers.html#watchedfilehandler>`__ for this log. That means that if you or your system moves the logfile (for example due to log rotation) then Raiden will detect that and close and reopen the log file handler with the same name.

Finally by default the output of the logs are in plain readable text format. In order to make them machine readable and parsable json add the ``--log-json`` argument.

Summing up these are the arguments you need to append if you want to disable the debug log and want to configure normal logging for up to debug statement in json inside a file called ``raiden.log``

``--disable-debug-logfile --log-config ":debug" --log-file raiden.log --log-json``
