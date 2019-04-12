Raiden on Private Network Tutorial
##################################

Introduction
============

This tutorial shows how to run Raiden on a private network, using the ``master`` branch (this is useful when you are working on a pull-request).  This tutorial assumes Ubuntu 18.04.2 LTS and ``bash``.

Creating a Virtual Environment
==============================

In a shell, run

.. code:: bash

 $ sudo apt-get install libncurses5-dev
 $ mkdir priv_chain

If ``mkdir`` fails, choose a different name, or move the existing ``priv_chain`` directory to somewhere else.

.. code:: bash

 $ cd priv_chain
 $ virtualenv -p python3.7 env
 $ source env/bin/activate

You should now be in the virtual environment, where all Python package installations are separately managed.

Now the command prompt should look like:

.. code:: bash

 (env) $


Install Raiden and dependencies
===============================

.. code:: bash

 (env) $ pwd
 <snip>/priv_chain
 (env) $ git clone https://github.com/raiden-network/raiden
 (env) $ cd raiden
 (env) $ pip install -r requirements.txt -c constraints.txt -e .

Launch a private network
========================

Installing Geth
---------------

Follow `the guide <https://geth.ethereum.org/install-and-build/Installing-Geth>`__ and install Geth. A command ``geth`` should be available in your shell. This guide assumes version 1.8.26, but other versions might work.

Preparing a genesis config
--------------------------

Prepare a file ``genesis.json`` with the following content (`@offerm <https://github.com/offerm>`__ kindly allowed to use his file here).

.. code:: bash

 (env) $ cd ..
 (env) $ pwd
 <snip>/priv_chain
 (env) $ cat genesis.json
 {
 "config": {
 "chainId": 4321,
 "homesteadBlock": 0,
 "eip150Block": 0,
 "eip155Block": 0,
 "eip158Block": 0,
 "ByzantiumBlock": 0
 },
 "alloc": {},
 "difficulty" : "0x1",
 "gasLimit"   : "0x9880000"
 }

Starting a chain
----------------

With the ``genesis.json`` you can initialize a blockchain.

.. code:: bash

 (env) $ pwd
 <snip>/priv_chain
 (env) $ geth --datadir blkchain1 init genesis.json
 (env) $ geth --rpc --datadir blkchain1 --networkid 4321 --rpcapi "eth,net,web3,txpool" console
 <snip>
 > personal.newAccount()
 "0xd4de892c06cf4a0557c7d515f79fd20b8356d6cf"

Copy the shown address somewhere.  And start mining on your own private blockchain.

.. code:: bash

 > miner.start()

In this console ``geth`` should keep running.

Figure out the contract version
===============================

Open a new console, and load the Python environment.

.. code:: bash

 $ pwd
 <snip>/priv_chain
 $ source env/bin/activate
 (env) $

In the ``raiden`` directory, figure out the value ``DEVELOPMENT_CONTRACT_VERSION``

.. code:: bash

 (env) $ cd raiden
 (env) $ grep 'DEVELOPMENT_CONTRACT_VERSION = ' -r .
 ./raiden/settings.py:DEVELOPMENT_CONTRACT_VERSION = '0.10.1'

Copy the shown version somewhere.

Define constants
================

The contract version will be used quite often, so let bash remember it.

.. code:: bash

 (env) $ export VERSION="0.10.1"

You will need your private key for the account you created.

.. code:: bash

 (env) $ cd ..
 (env) $ pwd
 <snip>/priv_chain
 (env) $ export PRIV_KEY=./blkchain1/keystore/UTC-<use TAB-completion to fill in>

If the TAB-completion shows more than two files, something has gone wrong. In that case, back up all files and start over.

The biggest 256-bit unsigned int is a useful default as deposit limits and the max number of TokenNetwork contracts.

.. code:: bash

 (env) $ export MAX_UINT256=115792089237316195423570985008687907853269984665640564039457584007913129639935

The RPC connection point is used often.

.. code:: bash

 (env) $ export PROVIDER="http://127.0.0.1:8545"


Deploy contracts
================

.. code:: bash

 (env) $ pwd
 <snip>/priv_chain
 (env) $ python -m raiden_contracts.deploy raiden --rpc-provider $PROVIDER --private-key $PRIV_KEY --gas-price 10 --gas-limit 6000000 --contracts-version $VERSION --max-token-networks $MAX_UINT256
