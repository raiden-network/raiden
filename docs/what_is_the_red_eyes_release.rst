What is the Raiden Red Eyes Release
************************************

*And what it is not*


.. toctree::
  :maxdepth: 2

Disclaimer!
-----------
**The Raiden Red Eyes release is considered safe to use on the main net. But since it is the first main net release and also acts as a bug bounty release, the amounts that can be deposited and transferred have been limited.**

Introduction
------------
The Red Eyes release is the first version of the Raiden Network that is deployed on the Ethereum main net.
The main goal of this release is to get the smart contracts and the core protocol battle tested on the main net.
As part of ensuring this, a `bug bounty <LINK TO BUG BOUNTY POST>`_ has been created for the release.
Furthermore this release shows a slightly simplified version of the Raiden API, but it should suffice to get people started doing payment using the Raiden Network.

The restrictions made to the Red Eyes release in order to mitigate risk in case of unexpected security issues are the following:

- A user cannot create a token network. `W-ETH <https://weth.io/>`_ will be the only registered token.
- The combined deposit of one channel is limited to 0.15 W-ETH. So 0.075 W-ETH worth of tokens per node.
- The total combined deposit of all channels across the whole network is limited to 250 W-ETH.

Below is a list of features included in the Red Eyes release along with a list of things that are scheduled for future releases and limitations of the release.

The Red Eyes release supports
-------------------------------

- Opening, closing and settling of payment channels.
- Direct and mediated (multi hop) transfers.
- Automatically joining a token network and connecting to peers.
- A :doc:`REST API <rest_api>` with endpoints for all functionalities.
- Only a token network for the `W-ETH <https://etherscan.io/address/0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2>`_ token.
- Restartability in case of a proper shutdown of the Raiden node.
- Topping up open channels

Along with above functionality some other considerable improvements have been made since the :doc:`Developer Preview Release<what_is_the_dev_preview>`:

- Rewritten and more gas efficient smart contracts.
- Recoverability in case a Raiden node shuts down unexpectedly.
- `Matrix <https://matrix.org/>`_ transport protocol.


The Red Eyes release is not
----------------------------

- Properly security audited, which is why deposit and transfer limitations have been made.
- Supporting a very efficient network topology. Currently all nodes need to have a complete view of the network to find paths for mediated transfers.
- Supporting atomic swaps.
- Supporting the functionality that allows for third party services to monitor channels on behalf of nodes.
- Supporting that third party services can do path finding on behalf of nodes.
- Supporting registration of more than one token network.


Other restrictions
------------------
Currently all nodes participating in a transfer need to be online in order for a transfer to be carried out. This means that users must run a full Raiden node to receive transfers too. The Red Eyes release does not offer a Raiden light client, it is however a goal to `implement a light client <https://github.com/raiden-network/raiden/issues/114>`_ in the future.

Versions
--------
Raiden follows `semver <http://semver.org/>`_ versioning (format ``{major}.{minor}.{patch}``). During the current alpha phase, the ``0.x.y`` series, we use the ``{minor}`` part to signify breaking changes.

The Raiden `smart contracts <https://github.com/raiden-network/raiden-contracts/tree/master/>`_ also have a version identifier, ``contract_version``, that corresponds to the Raiden software version. During the ``0.x.y`` series they will follow the Raiden release versions only on the ``{major}.{minor}`` parts; the patch part is replaced by ``_``, e.g. ``contract_version = "0.1._";``.

This allows you to be sure, that the version of the smart contract ABI matches those that are deployed on the testnet. In other words, if the smart contract code changes, the Raiden version will at least increase the ``{minor}`` part, and, if a Raiden release introduces a breaking change, the smart contract versions will also be increased.

**Note for Developers:**
The version reported by ``raiden.utils.get_system_spec()`` depends on the ``pkg_resources`` version, which is configured
during ``install`` based on git tags. If you are working on an editable source install from git, i.e. ``pip install -e .``, you should make sure to

- add ``fetch = +refs/tags/*:refs/tags/*`` to the ``[remote "origin"]`` entry of your ``.git/config`` file (`see here
  <https://stackoverflow.com/a/16678319>`_ for details).
- call ``pip install -e .`` again after every new (tagged) release.
