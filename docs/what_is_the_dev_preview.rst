What is the Raiden Developer Preview
************************************

*And what is it not*


.. toctree::
  :maxdepth: 2

Disclaimer!
-----------
**The Raiden Developer Preview is not at a Minimum Viable Product (MVP) stage, and hence shouldn't be considered safe to use on the Ethereum main net.**


Introduction
------------
The goal with releasing the Developer Preview is to give developers a chance to get familiar with the
Raiden API and to figure out what will be possible to do with Raiden, once it's fully ready.

Below is a listing of things that are included in the Developer Preview together with things that are in the roadmap, but are not yet implemented.


The Developer Preview includes
-------------------------------

- Opening, closing and settling of payment channels.
- Direct and mediated (multi hop) transfers.
- Automatically joining a token network and connecting to peers
- A :doc:`REST API <rest_api>` with endpoints for all functionality.
- Possibility to create token networks for all ERC20 tokens.
- Restartability of Raiden nodes.
- :ref:`ERC20 token swaps <token_swaps>`.


The Developer Preview is not
----------------------------

- Safe to use in the main net and we do not recommend that anyone deploy the contracts to the Ethereum main net.
- Properly security audited and should, hence, not be used to transfer anything of actual value.
- Capable of recovering the state of a Raiden node if Raiden did not shut down correctly.
- Supporting a very efficient network topology. Currently all nodes need to have a complete view of the network to find paths for mediated transfers.


Other restrictions
------------------
Currently all nodes participating in a transfer need to be online in order for a transfer to be carried out. This means that users must run a full Raiden node to receive transfers too. The Developer Preview does not offer a Raiden light client, it is however a goal to `implement a light client <https://github.com/raiden-network/raiden/issues/114>`_ in the future.

