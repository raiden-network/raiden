Contract Proxies Guide
######################

Introduction
============

A Raiden node accesses smart contracts through wrappers called proxies. The proxies are implemented in ``raiden/network/proxies`` directory. The proxies are supposed to be used with some special care, and they are implemented in a specific way.

The complication exists because there is always the possibility of a race between our node, the blockchain(s) and other parties. The Raiden node usually recognizes events on the blockchain only after some confirmation period. By the time the Raiden node recognizes an onchain event, the Raiden node has seen several blocks have been mined on top. However, when Raiden posts a transaction to the blockchain, the transaction is sent to miners who operate on the newest available block.

The proxies try to prevent the users from spending gas costs for transactions that fail anyway, and also to give a reasonable diagnosis why a transaction doesn't (or didn't go through).

A Proxy's Workflow
==================

Read-only case
--------------

If the call is read-only, the proxy never throws a transaction to the blockchain. The proxy asks the Ethereum client to execute the call in the specified blockhash.

State-modifying case
--------------------

If the call modifies the state, the proxy does the following things in the successful case:

1. the proxy checks conditions on the specified block, and sees whether the call would fail (the post-condition checks)
2. the proxy then asks the Ethereum client to estimate gas, which might fail.
3. the proxy then asks the Ethereum client to submit the transaction to the blockchain.
4. the proxy sees the transaction receipt and sees if it's successful.

When the precondition checks fail, the proxy raises ``BrokenPreconditionError``, blaming the caller for making a call without proper checks.

When the gas estimation fails, the proxy performs additional checks on the latest available block in order to determine the cause of the failure.

When the transaction was included in a block but the execution has failed, the proxy performs additional checks on that block in order to determine
the cause of the failure.

Depending on the cause of the failure, the proxy raises different kinds of exceptions. If you use the proxies, you'll need to
make sense of these exceptions (see below).

A Guide for Using Proxies
=========================

Before calling a proxy, make sure that the call is going to succeed in a confirmed block.
And then, pass the blockhash of the confirmed block to the proxy when you call it.

The proxy checks the preconditions on the confirmed block. If any of the preconditions fail,
it raises `BrokenPreconditionError`. This means there is a mistake in the Raiden codebase,
and a check must be added before calling the proxy.

When the proxy doesn't raise an exception, the call was successful. A transaction was included
in a block and the transaction has been executed successfully. Moreover the proxy has waited
for the block to be confirmed so that the state change is visible to the Raiden node.

When the proxy raises ``RaidenUnrecoverableError``, it means that there is a bug in the
client codebase or in the smart contracts.

When the proxy raises ``RaidenRecoverableError``, it might mean:

- somebody else posted another transaction that altered the chain state in a conflicting way.
- a third party smart contract behaved weirdly.

The proxy tries hard to determine whether the problem is in the Raiden codebase (client
or smart contract), but ultimately, if the proxy is not sure, it raises ``RaidenRecoverableError``.


A Guide for Implementing Proxies
================================

When you implement proxies, the best documentation to follow is the source of TokenNetwork proxy.

Sometimes precondition checks are impossible because the specified block is too old (pruned in the Ethereum client).
In this case, the precondition check can be skipped.
