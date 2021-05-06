:orphan:

.. _manual_udc_deposit:

Manually depositing tokens to pay the services
==============================================

To pay the services, you have to lock some of your Raiden tokens in the ``UserDeposit`` contract.
Normally the Raiden Wizard or some other auxilliary scripts would do the contract interaction for you.
In this section, we will briefly explain how it can be done manually so you are able to use Raiden without them.

All services that are registered in the service registry of a given network will use one shared instance of ``UserDeposit``.
You can obtain the address of the contract from

    ``https://github.com/raiden-network/raiden-contracts/blob/master/raiden_contracts/data/deployment_services_<network>.json``

where ``network`` is one of ``mainnet``, ``ropsten``, ``rinkeby`` or ``goerli``.

As an example, suppose we want to run a Raiden node with address ``0x3040435D7F1012e861f0B0989422a47D1825F120`` on the mainnet
and deposit 10 Raiden tokens (10**19 REI) for it to use. Here we use `MetaMask <https://metamask.io>`_ to access our wallet
and the contract interface of `Etherscan <https://etherscan.io>`_ to do the transactions. Of course, you can also use another
service or your own Ethereum node.

We log into MetaMask with our account that holds the Raiden tokens (which should be a different account than the one we use with
Raiden, as the latter is supposed to be used with Raiden only.) To find the ``UserDeposit`` contract, we take a look at ``deployment_services_mainnet.json``:

.. code-block:: none

    {
        "contracts_version": null, "chain_id": 1,
        (...)
        "UserDeposit": {
            "address": "0x53Cc1decDD7d452c8844a5f383e23AD479A1f614",
            (...)


We can then look up the contract address on Etherscan, and use Etherscan's "read/write contract" panels to interact with it.
The Raiden token (RDN) can be searched by name on Etherscan, or we can look up its address in the ``UserDeposit`` contract's
``token`` property. On the testnets, the token symbol is SVT (service token) rather than RDN and it may not be possible
to find the token by name, but it can always be found in ``UserDeposit.token``.


As usual with ERC-20 tokens, we need to call two contract functions:

.. code-block:: none

    approve(0x53Cc1decDD7d452c8844a5f383e23AD479A1f614, 10000000000000000000)

on the RDN (or SVT) token contract, to allow the ``UserDeposit`` contract to move the 10 RDN, and

.. code-block:: none

    deposit(0x3040435D7F1012e861f0B0989422a47D1825F120, 10000000000000000000)

on the ``UserDeposit`` contract.