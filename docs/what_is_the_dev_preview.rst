What is the Raiden Developer Preview
************************************

*And what it is not*


.. toctree::
  :maxdepth: 2

Disclaimer!
-----------
**The Raiden Developer Preview is not at a Minimum Viable Product (MVP) stage, and hence shouldn't be considered safe to use on the Ethereum main net.**


Introduction
------------
The goal of releasing the Developer Preview is to give developers a chance to get familiar with the
Raiden API and to get an idea of the full potential of Raiden once all issues are addressed.

Below is a listing of things that are included in the Developer Preview together with things that are in the roadmap, but are not yet implemented.


The Developer Preview supports
-------------------------------

- Opening, closing and settling of payment channels.
- Direct and mediated (multi hop) transfers.
- Automatically joining a token network and connecting to peers.
- A :doc:`REST API <rest_api>` with endpoints for all functionalities.
- Possibility to create token networks for all ERC20 tokens.
- Restartability in case of a proper shutdown of the Raiden node.
- :ref:`ERC20 token swaps <token-swaps>`.


The Developer Preview is not
----------------------------

- Safe to use in the main net and we do not recommend that anyone deploy the contracts to the Ethereum main net.
- Properly security audited and should, hence, not be used to transfer anything of considerable value.
- Capable of recovering the state of a Raiden node if Raiden did not shut down correctly.
- Supporting a very efficient network topology. Currently all nodes need to have a complete view of the network to find paths for mediated transfers.


Other restrictions
------------------
Currently all nodes participating in a transfer need to be online in order for a transfer to be carried out. This means that users must run a full Raiden node to receive transfers too. The Developer Preview does not offer a Raiden light client, it is however a goal to `implement a light client <https://github.com/raiden-network/raiden/issues/114>`_ in the future.

The transport layer used in the Developer Preview is not very sophisticated and thus it is storing the IP addresses of all nodes participating in the `Endpoint Registry <https://github.com/raiden-network/raiden/blob/master/raiden/smart_contracts/EndpointRegistry.sol>`_ smart contract. In the future it is planned to use something like Whisper for the transportation layer.

Versions
--------
Raiden follows `semver <http://semver.org/>`_ versioning (format ``{major}.{minor}.{patch}``). During the current alpha phase, the ``0.x.y`` series, we use the ``{minor}`` part to signify breaking changes.

The Raiden `smart contracts <https://github.com/raiden-network/raiden/tree/master/raiden/smart_contracts>`_ also have a version identifier, ``contract_version``, that corresponds to the Raiden software version. During the ``0.x.y`` series they will follow the Raiden release versions only on the ``{major}.{minor}`` parts; the patch part is replaced by ``_``, e.g. ``contract_version = "0.1._";``.

This allows you to be sure, that the version of the smart contract ABI matches those that are deployed on the testnet. In other words, if the smart contract code changes, the Raiden version will at least increase the ``{minor}`` part, and, if a Raiden release introduces a breaking change, the smart contract versions will also be increased.

**Note for Developers:**
The version reported by ``raiden.utils.get_system_spec()`` depends on the ``pkg_resources`` version, which is configured
during ``install`` based on git tags. If you are working on an editable source install from git, i.e. ``pip install -e .``, you should make sure to

- add ``fetch = +refs/tags/*:refs/tags/*`` to the ``[remote "origin"]`` entry of your ``.git/config`` file (`see here
  <https://stackoverflow.com/a/16678319>`_ for details).
- call ``pip install -e .`` again after every new (tagged) release.
