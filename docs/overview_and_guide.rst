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
