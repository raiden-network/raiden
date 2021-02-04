Refunds
=======

Why Would Anyone Do Refunds?
----------------------------

Sometimes, a payment can’t proceed as planned. This usually happens when
nodes go offline, the channel capacity decreases, nodes change their
behavior (e.g. fees) or nodes misbehave for other reasons.

When that happens, the initiator could just start a new payment over a
different route until it succeeds. But the funds used in the first
transfer will stay locked until the failed payment times out, thereby
reducing the networks liquidity.

Refunds return the funds to undo the payment to a certain degree. If the
funds are returned all the way to the initiator, he can remove the lock
by revealing the secret. Refunds to mediators allow mediators to retry
the mediation along a different path.

Current Implementation
----------------------

At the moment, refunds are always propagated all the way back to the
initiator. The initiator does not do anything on receiving the refund
and the payment times out. This is the worst possible apporoach because:

-  Refunds don’t provide any benefit
-  Doing refunds locks up additional funds until the payment times out
-  Refunds significantly increase complexity of the mediation code

The light client has an incomplete and untested refund implementation,
and Andre prefers to “research better approaches to the issue than to
revive the Refund”.

Potential Solutions
-------------------

Remove Refunds
~~~~~~~~~~~~~~

Without significant improvements in our refund handling, the benefits
are dubious. The upside of removing refunds is quite clear: reduced
complexity in implementation, testing, documentation and the overall
concept.

Fix Existing Refunds
~~~~~~~~~~~~~~~~~~~~

The existing implementation can certainly be improved, but there are
open questions for nearly every potential improvement. Some of the
questions are:

-  Should the refunds go back along the same route (might lack capacity)
   or choose a new route (who will pay the PFS)?
-  How likely are refunds to succeed?
-  Is the increased liquidity due to early lock release bigger than the
   amount of tokens locked by the refunds during the refund process (and
   until the timeout if the refund fails)?
-  Will refunds be visible to end users? How?
-  Should refunds incur mediation fees?
-  Should mediation fees for the forward payment be refunded?
-  Should the initiator reveal the secret for a fully refunded payment
   even when he will have to pay mediation fees?

Try to Improve on Existing Refunds
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Even if the current refunds are useless, they might serve as a foudation
for a better but similar refund mechanism. Things to consider:

-  Can we remove the liquidity requirements for refunds by going back
   along the original route? The refund might be able to free the locked
   liquidity on each step instead of locking up more tokens, even before
   the secret is revealed
-  The mediation code could be simplified by limiting the allowed cases
   (e.g. only refund back all the way to the initiator, no new routes
   tried by mediators)

Use Different Refund Approach
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

There are other ways to do refunds or cancel payments, which might be
worth further investigation:

-  One suggestions by Augusto:
   https://github.com/raiden-network/raiden-contracts/issues/1216 (could
   not be made into a viable suggestion, yet)
-  Lightning has some kind of refund or cancellation mechanism

Final Decision by the Team
--------------------------

After discussion, only two options were left that could be implemented
without huge effort:

-  Removing refunds
-  Do refunds back to the initiator, including all fees. Revealing the
   secret will free up the locked funds, without moving any tokens. This
   way, everyone has an incentive to participate.

The seconds approach still has the problem of locking up additional
funds and potentially failing. The benefits are too small to justify the
increased complexity. So the recommendation is to remove the refunds.

This discussion was based on the assumption of strict routing,
i.e. strictly following the route planned by the initiator. If we allow
retrying different routes at any node, the results might be different.
