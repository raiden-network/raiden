Withdraw & Expiry
=================

**Status**: proposed
**Deciders**: @konradkonrad @palango @hackaugusto @rakanalh
**Date**: 2019-07-03

Context and Problem Statement
=============================

Withdraw functionality was introduced into Raiden to enable users to withdraw funds from their open channels into their accounts.
The implemented flow works as follows:

1. Node (A) initiates the withdraw by dispatching `ActionInitWithdraw` with a monitonic total withdraw value.
2. Node (A) sends a signed `WithdrawRequest` message to partner to agree on the new total withdraw.
3. Node (B) receives the withdraw request, validates it and replies with a signed `WithdrawConfirmation` message to node (A).
4. Node (A) receives the withdraw confirmation, validates it and uses signatures from step (1) and step(2) to send an on-chain transaction
   to withdraw the funds.

Here, a problem arises when node (B) is unavailable or is not cooperative. In this case, node (A) would have sent a withdraw request,
locked part or all of it's deposited amount for withdraw and no confirmation was received from node (B). This will lead to node (A) not being able
to use the locked funds for withdraw until node (B) replies. In the case of node (B) not being cooperative on this withdraw request, node (A)'s
locked withdraw funds are unavailable indefinitely until the channel is closed.

Considered Options
==================

* **Option 1**: Node (A) could close the channel with node (B). In this case, node (A) gets back the funds it originally locked for withdraw.
  One downside of this approach is forcing the user to close the channel just to be able to unlock the withdraw funds. However, the counter-argument
  for this downside is a question of whether the user would want to have an open channel with a non-cooperating partner node.

* **Option 2**: Implement withdraw expiry messages where node (A) calculates a block at which the withdraw request expires. Node (B) will have to be
  aware of this expiry option and be able to react to a `WithdrawExpired` message which will clear the expired withdraw state for the partner.
  This approach resolves the issue of having the locked funds indefinitely or until the channel is closed with a non-cooperating partner node because
  once the withdraw request expires, node (A) will remove the expired total withdraw state and locked withdraw will be unlocked.

Examples of Option 2
====================

Simple:
-------

- Node (A)'s balance = 100 tokens
- Node (A) requests a withdraw of 50 tokens. In this case, usable balance of node (A) is 50 (assuming it did not send/receive transfers to/from node (B)).
  `total_withdraw=50`.
- Node (B) does not confirm with withdraw.
- Node (A) sends node (B) a `WithdrawExpired` message. Node (A) only had 1 pending withdraw state of 50.
  Before sending `WithdrawExpired`, node (A) clears the expired withdraw state and `total_withdraw` is set to 0 because that is the only withdraw
  state that was requested.


Complex:
--------

- Node (A)'s balance = 100 tokens
- Node (A) requests a withdraw of 10 tokens. In this case, usable balance of node (A) is 50 (assuming it did not send/receive transfers to/from node (B)).
  `total_withdraw=10`.
- Node (A) requests a withdraw of another 10 tokens. `total_withdraw=20`.
- Node (A) requests a withdraw of another 20 tokens. `total_withdraw=40`.
- Node (A) withdraw states look as follows
```
[
  {
    "total_withdraw": 10,
  },
  {
    "total_withdraw": 20,
  }
  {
    "total_withdraw": 30,
  }
]
```
- Node (B) does not confirm any withdraw.
- Node (A) sends node (B) a `WithdrawExpired` message for the first withdraw request which had a `total_withdraw=10`.
  Before sending `WithdrawExpired`, node (A) clears the expired withdraw state `total_withdraw=10`. However, that doesn't affect node (A)'s `total_withdraw`
  because the latest one is 30 and stays 30.
- Node (A) sends node (B) a `WithdrawExpired` again for the second withdraw request which had a `total_withdraw=20`. Same as before applies.
- Node (A) sends node (B) a `WithdrawExpired` again for the third and last withdraw request which had a `total_withdraw=30`. Similar to the simple case,
  this was the only withdraw state that is pending, therefore expiring this withdraw state means that the `total_withdraw` of node (A) goes back to zero.


Why Nonce was included in a non-balance proof message
=====================================================

Previously, only balance-proof messages had a nonce. The nonce value provides certain guarantees one of which is the fact that we are
able to process messages in the exact order in which they were sent.
Though `WithdrawRequest`, `WithdrawConfirmation` and `WithdrawExpired` messages are not balance-proof messages,
a nonce value was required to make sure that these messages are also processed in the order in which they were sent. To accomodate for this change,
the nonce field has to be decoupled from being based on the latest balance proof to a value that is maintained for the two sides of the channel state
so that the next value is requested by either balance-proof based messages or withdraw messages.
