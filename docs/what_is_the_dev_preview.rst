What is the Raiden Developer Preview
####################################

And what is it not
------------------


Contents:

.. toctree::
   :maxdepth: 2


Disclaimer!
***********

**The Raiden Developer Preview is not at a *Minimum Viable Product* (MVP) stage, and hence shouldn't be considered safe to use on the Ethereum main net.**


Introduction
************
The goal with releasing the Developer Preview is to give developers a chance to get familiar with the
Raiden API and to figure out what will be possible to do with Raiden, once it's fully ready.

Below is a listing of things that are included in the Developer Preview together with things that are in the roadmap, but are not yet implemented.


What it is::
------------

- Capable of opening, closing and settling payment channels.
- Capable of doing direct and mediated (multi hop) transfers.
- Capable of automatically joining a token network and connect to peers
- It provides a REST API with endpoints for all functionality.
- It supports token networks for all ERC20 tokens.
- It supports restartability of Raiden nodes.
- It supports ERC20 token swaps.


What it is not::
----------------

- It is not safe to use in the main net and we do not recommend that anyone deploy the contracts to the Ethereum main net.
- It is not yet properly security audited and should, hence, not be used to transfer anything of actual value.
- It is not capable of recovering the state of a Raiden node if Raiden did not shut down correctly.
- It does currently not support a very efficient network topology. Currently all nodes need to have a complete view of the network to find paths for mediated transfers.


Other restrictions::
--------------------
Currently all nodes participating in a transfer need to be online in order for a transfer to be carried out. This means that users must run a full Raiden node to receive transfers too. The Developer Preview does not offer a Raiden light client, it is however a goal to `implement a light client <https://github.com/raiden-network/raiden/issues/114>`_ in the future.

