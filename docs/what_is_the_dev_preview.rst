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
