Raiden System Overview and User Guide
===============================================


.. toctree::
   :maxdepth: 2



Introduction
=============
Raiden is a payment channel implementation which provides scalable, low latency, and cheap token transfers for Ethereum.


Getting Started
==================

In order to install Raiden at the moment you need to clone it from Github and compile it from source

Dependencies
---------------

* You need to make sure that your system has `solc`, the ethereum solidity compiler installed. Refer to `its documentation <http://solidity.readthedocs.io/en/latest/installing-solidity.html>`_ for the installation steps.
* You will need to have the go-ethereum client installed in your system. Check `this link <https://github.com/ethereum/go-ethereum/wiki/Building-Ethereum>`_ for instructions.
* You will also need to obtain the `system dependencies for pyethapp <https://github.com/ethereum/pyethapp/#installation-on-ubuntudebian>`_.



Installation
-------------

Clone the repository::


    git clone https://github.com/raiden-network/raiden.git


Navigate to the directory::

    cd raiden

It's advised to create a `virtualenv <http://docs.python-guide.org/en/latest/dev/virtualenvs/>`_ for raiden and install all python dependencies there.

After you have done that you can proceed to install the dependencies::

    pip install --upgrade -r requirements.txt
    python setup.py develop

You will also need an ethereum client that is connected to the Ropsten testnet. 

Geth
----

Install Geth::

    sudo apt-get install geth

Sync Geth to the Ropsten network.  If you have previously used geth to connect to the Morden testnet, you will need to first delete the database::

    geth --testnet removedb

Run Geth and sync::

    geth --testnet --rpc

Create a new account on the Ropsten testnet::

    geth --testnet account new


After account creation, launch raiden with the path of your keystore supplied and the RPC endpoint of the parity client (defaults show): 

     raiden --keystore-path ~/.ethereum/testnet/keystore --eth-rpc-endpoint 127.0.0.1:8545

Select the ethereum account when prompted, and type in the account's password. 

Parity (Experimental)
------------------------

    sudo snap install parity --edge && sudo cp /snap/parity/current/bin/parity /usr/bin/parity

Run the parity client and let it sync to the Ropsten testnet::

     parity --chain ropsten --bootnodes "enode://20c9ad97c081d63397d7b685a412227a40e23c8bdc6688c6f37e97cfbc22d2b4d1db1510d8f61e6a8866ad7f0e17c02b14182d37ea7c3c8b9c2683aeb6b733a1@52.169.14.227:30303,enode://6ce05930c72abc632c58e2e4324f7c7ea478cec0ed4fa2528982cf34483094e9cbc9216e7aa349691242576d552a2a56aaeae426c5303ded677ce455ba1acd9d@13.84.180.240:30303"

After syncing the chain, create an account on the Ropsten testnet by navigating to the url that parity shows.  It is usually::

     http://127.0.0.1:8180

After account creation, launch raiden with the path of your keystore supplied and the RPC endpoint of the parity client (defaults show): 

     raiden --keystore-path ~/.local/share/io.parity.ethereum/keys/test --eth-rpc-endpoint 127.0.0.1:8545

Select the ethereum account when prompted, and type in the account's password. 
 