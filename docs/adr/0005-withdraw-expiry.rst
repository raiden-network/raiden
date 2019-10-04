Withdraw & Expiry
=================

**Status**: implemented
**Deciders**: @konradkonrad @palango @hackaugusto @rakanalh
**Date**: 2019-07-03

Context and Problem Statement
=============================

Withdraw functionality was introduced into Raiden to enable users to withdraw funds from their open channels into their accounts.
The implemented flow works as follows:

1. Alice initiates the withdraw by dispatching `ActionInitWithdraw` with a monitonic total withdraw value.
2. Alice sends a signed `WithdrawRequest` message to its partner to agree on the new total withdraw.
3. Bob receives the withdraw request, validates it and replies with a signed `WithdrawConfirmation` message to Alice.
4. Alice receives the withdraw confirmation, validates it and uses signatures from step (2) and step(3) to send an on-chain transaction
   to withdraw the funds.

Here, a problem arises when Bob is unavailable or is not cooperative. In this case, Alice would have sent a withdraw request,
locked part or all of its deposited amount for withdraw and no confirmation was received from Bob. This will lead to Alice not being able
to use the locked funds for withdraw until Bob replies. In the case of Bob not being cooperative on this withdraw request, Alice's
locked withdraw funds are unavailable indefinitely until the channel is closed.

Considered Options
==================

* **Option 1**: Alice could close the channel with Bob. In this case, Alice gets back the funds it originally locked for withdraw.
  One downside of this approach is forcing the user to close the channel just to be able to unlock the withdraw funds. However, the counter-argument
  for this downside is a question of whether the user would want to have an open channel with a non-cooperating partner node.

* **Option 2**: Implement withdraw expiry messages where Alice calculates a block at which the withdraw request expires. Bob will have to be
  aware of this expiry option and be able to react to a `WithdrawExpired` message which will clear the expired withdraw state for the partner.
  This approach resolves the issue of having the locked funds indefinitely or until the channel is closed with a non-cooperating partner node because
  once the withdraw request expires, Alice will remove the expired total withdraw state and locked withdraw will be unlocked.

Decision
========

Option 2 of `WithdrawExpiry` has the disadvantage of adding a collection of new messages to the
protocol, which could be seen as further complication of the protocol. However, it has the advantage that
amounts locked for withdraw can be unlocked and used for transfers instead in case of an expired withdraw attempt.

Though Option 1 can be argued that its much simpler, the benefit of unlocking funds previously locked for withdraw was seen
as more viable solution even with the added complexity.

Examples of Option 2
====================

Simple:
-------

- Alice's balance = 100 tokens
- Alice requests a withdraw of 50 tokens. In this case, usable balance of Alice is 50 (assuming it did not send/receive transfers to/from Bob).
  `total_withdraw=50`.
- Bob does not confirm with withdraw.
- Alice sends Bob a `WithdrawExpired` message. Alice only had 1 pending withdraw state of 50.
  Before sending `WithdrawExpired`, Alice clears the expired withdraw state and `total_withdraw` is set to 0 because that is the only withdraw
  state that was requested.


Complex:
--------

- Alice's balance = 100 tokens
- Alice requests a withdraw of 10 tokens. In this case, usable balance of Alice is 50 (assuming it did not send/receive transfers to/from Bob).
  `total_withdraw=10`.
- Alice requests a withdraw of another 10 tokens. `total_withdraw=20`.
- Alice requests a withdraw of another 20 tokens. `total_withdraw=40`.
- Alice withdraw states look as follows
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
- Bob does not confirm any withdraw.
- Alice sends Bob a `WithdrawExpired` message for the first withdraw request which had a `total_withdraw=10`.
  Before sending `WithdrawExpired`, Alice clears the expired withdraw state `total_withdraw=10`. However, that doesn't affect Alice's `total_withdraw`
  because the latest one is 30 and stays 30.
- Alice sends Bob a `WithdrawExpired` again for the second withdraw request which had a `total_withdraw=20`. Same as before applies.
- Alice sends Bob a `WithdrawExpired` again for the third and last withdraw request which had a `total_withdraw=30`. Similar to the simple case,
  this was the only withdraw state that is pending, therefore expiring this withdraw state means that the `total_withdraw` of Alice goes back to zero.


Why Nonce was included in a non-balance proof message
=====================================================

Previously, only balance-proof messages had a nonce. The nonce value provides certain guarantees one of which is the fact that we are
able to process messages in the exact order in which they were sent.
Though `WithdrawRequest`, `WithdrawConfirmation` and `WithdrawExpired` messages are not balance-proof messages,
a nonce value was required to make sure that these messages are also processed in the order in which they were sent. To accomodate for this change,
the nonce field has to be decoupled from being based on the latest balance proof to a value that is maintained for the two sides of the channel state
so that the next value is requested by either balance-proof based messages or withdraw messages.
