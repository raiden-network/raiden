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
---------------

These are the currently deployed raiden contract addresses for the Ropsten testnet:

* Netting Channel Library: 0x0966d741b83de207579fbd8fd3097dcf7c294fa4_
* Channel Manager Library: 0x7f77e6687d1647d55ea89315267cc347bc3a212b_
* Registry Contract: 0xce30a13daa47c0f35631e5ed750e39c12172f325_
* Discovery Contract: 0xaecb64f87c7fa12d983e541eabb0064fc9d87c4f_

.. _0x0966d741b83de207579fbd8fd3097dcf7c294fa4: https://ropsten.etherscan.io/address/0x0966d741b83de207579fbd8fd3097dcf7c294fa4#code
.. _0x7f77e6687d1647d55ea89315267cc347bc3a212b: https://ropsten.etherscan.io/address/0x7f77e6687d1647d55ea89315267cc347bc3a212b#code
.. _0xce30a13daa47c0f35631e5ed750e39c12172f325: https://ropsten.etherscan.io/address/0xce30a13daa47c0f35631e5ed750e39c12172f325#code
.. _0xaecb64f87c7fa12d983e541eabb0064fc9d87c4f: https://ropsten.etherscan.io/address/0xaecb64f87c7fa12d983e541eabb0064fc9d87c4f#code
