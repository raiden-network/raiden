Raiden Developer Onboarding Guide
#################################
.. toctree::
  :maxdepth: 2

Introduction
============
This is a general onboarding guide whose main purpose is to help people who want to develop Raiden. It provides an in-depth explanation of the protocol followed by an explanation of the architecture.

The Raiden Protocol
===================

In this section we will have the general explanation of how the Raiden protocol works, starting from the smart contracts and ending with the offchain messages that are exchanged between Raiden nodes.
For a more formal definition of the protocol please refer to the `specification <https://raiden-network-specification.readthedocs.io/en/latest/>`_.

Smart contracts
***************

Raiden has 4 smart contracts that are needed to support the protocol. They can all be found at the `smart contracts repository <https://github.com/raiden-network/raiden-contracts>`_. The repository also contains scripts to deploy and verify the contracts on different networks.

Token Network Registry
~~~~~~~~~~~~~~~~~~~~~~

The `Token Network Registry <https://github.com/raiden-network/raiden-contracts/blob/04fe5a6c33b2a34cd893c5e546b8df949e194947/raiden_contracts/contracts/TokenNetworkRegistry.sol>`_ contract is the main component that defines a deployment of the Raiden Network.

It is a registry of all different TokenNetwork contracts, one for each token. When someone wants to register a Token and create a network for it they interact with the TokenNetworkRegistry's `createERC20TokenNetwork() <https://github.com/raiden-network/raiden-contracts/blob/04fe5a6c33b2a34cd893c5e546b8df949e194947/raiden_contracts/contracts/TokenNetworkRegistry.sol#L59>`_ function.

Token Network
~~~~~~~~~~~~~

Once a token has been registered with the registry a new `Token Network <https://github.com/raiden-network/raiden-contracts/blob/04fe5a6c33b2a34cd893c5e546b8df949e194947/raiden_contracts/contracts/TokenNetwork.sol>`_ is created for that Token. This is the main contract with which to interact for all onchain channel operations for that token.

Secret Registry
~~~~~~~~~~~~~~~

The `Secret Registry <https://github.com/raiden-network/raiden-contracts/blob/04fe5a6c33b2a34cd893c5e546b8df949e194947/raiden_contracts/contracts/SecretRegistry.sol>`_ is a contract that is deployed along with the ``TokenNetworkRegistry`` and together they define a deployment of the protocol.

It is used when a user needs to `register <https://github.com/raiden-network/raiden-contracts/blob/04fe5a6c33b2a34cd893c5e546b8df949e194947/raiden_contracts/contracts/SecretRegistry.sol#L20>`_ a secret onchain to prove that they knew the secret for a pending transfer before the block of the lock expiration has come.

Endpoint Registry
~~~~~~~~~~~~~~~~~

The `Endpoint Registry <https://github.com/raiden-network/raiden-contracts/blob/04fe5a6c33b2a34cd893c5e546b8df949e194947/raiden_contracts/contracts/EndpointRegistry.sol>`_ contract is a contract used only by the now deprecated `UDP transport <https://github.com/raiden-network/raiden/tree/3ae9ecccdf5d48fd5a9a07fae4752d4971cf6868/raiden/network/transport/udp>`_.

It serves as a mapping between user's ethereum addresses and ip addresses so that the transport layer knows where to send messages to.


Channel Opening Lifecycle
*************************

.. figure:: images/channel_open_deposit.png
    :width: 600px

    The channel opening lifecycle

A channel between two participants can be `opened <https://github.com/raiden-network/raiden-contracts/blob/04fe5a6c33b2a34cd893c5e546b8df949e194947/raiden_contracts/contracts/TokenNetwork.sol#L253>`_ by anyone. But there can be only one channel open between two participants at any time.

Once the channel is open then, anyone can `deposit <https://github.com/raiden-network/raiden-contracts/blob/04fe5a6c33b2a34cd893c5e546b8df949e194947/raiden_contracts/contracts/TokenNetwork.sol#L307`_ an amount of tokens for either of the two participants. Depositing is done via idempotent calls. That's why the function is called ``setTotalDeposit``, so that if it's called multiple times the result is always going to be the same. The function does not deposit a new amount each time but instead alters the amount of the total deposit that should be in the contract for a participant.


At this point the channel is active and payments can be made.

.. note::
   The withdraw functionality of the contract is currently disabled

At any point and if both participants agree they can also `withdraw <https://github.com/raiden-network/raiden-contracts/blob/04fe5a6c33b2a34cd893c5e546b8df949e194947/raiden_contracts/contracts/TokenNetwork.sol#L375>`_ tokens from the contract via an onchain transaction.


Messages for a happy transfer
*****************************


Routing
*******

Pending Transfers
******************

Close/Settlement Lifecycle
**************************

Unlocking Pending Transfers
***************************


Raiden Architecture
===================
