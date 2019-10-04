Raiden Glossary
===============

.. glossary::
   :sorted:

   payer
       In a channel relationship between two raiden nodes the payer is the participant who sends a transfer.

   payee
       In a channel relationship between two raiden nodes the payee is the participant who receives a transfer

   initiator
       In a payment the initiator is the raiden node which starts the payment

   target
       In a payment the target is the raiden node for which the payment sent by the initiator is intended

   MediatedTransfer
       A mediated transfer is a hashlocked transfer between an initiator and a target propagated through nodes in the network.

   RefundTransfer
       A refund transfer is a special type of MediatedTransfer that is used when a node can no longer propagate a transfer and a routing backtrack needs to be done.

   reveal timeout
       The number of blocks in a channel allowed for learning about a secret being revealed through the blockchain and acting on it.

   payment channel
       The on-chain payment channel between two raiden nodes.

   settlement timeout
   settlement window
       The number of blocks after the closing of a channel within which the counterparty is able to call ``updateNonClosingBalanceProof`` with the latest :term:`balance proof` they received.

   merkletree root
   locksroot
       The root of the ``merkle tree`` which holds the hashes of all the locks in the channel.

   transfer
       In Raiden a transfer denotes a single hop transfer of tokens, either direct or hash time locked inside a payment channel.

   payment
       In Raiden a payment denotes the process of sending tokens from one account to another. A payment has an initiator and a target and can be composed of multiple transfers.

   transferred amount
       The transferred amount is the total amount of tokens one participant of a payment channel has sent to his counterparty.

   locked amount
       The locked amount is the total amount of tokens one participant of a payment channel has locked in pending transfers towards his counterparty

   channel capacity
       A channel's capacity is the sum of the total deposits minus the sum of the total withdraws of both its participants. It is also the sum of the channel participants :term:`balance`.

   balance
       The balance :math:`B_n` of a channel participant :math:`P` is his total deposit :math:`P_d` along with the amount of tokens he received :math:`P_r` minus the amount :math:`P_s` of token he has sent. So :math:`B_n = P_d + P_r - P_s`

   locked balance
       The locked balance :math:`B_l` of a channel participant is the sum of the locked amount for all pending transfers :math:`T_p`. So :math:`B_l = \sum_{k=0}^{N-1} T_p` where :math:`N` is the number of pending transfers.

   available balance
       The available balance :math:`B_a` of a channel participant is :math:`B_a = B_n - B_l`.

   balance proof
       Balance proof is any kind of message used in order to cryptographically prove on the blockchain what the latest :term:`transferred amount` and :term:`locked amount` received from a counter party is.

   hashlock
       A hashlock is the hashed secret that accompanies a locked message: ``sha3(secret)``.

   lock expiration
       The lock expiration is the highest block_number until which the transfer can be settled.

   SecretRequest
       The secret request message is sent by the target of a mediated transfer to its initiator in order to request the secret to unlock the transfer.

   RevealSecret
       The reveal secret message is sent to a node that is known to have an interest to learn the secret.

   secret message
       The secret message is a message containing the secret and used for synchronization between mediated transfer participants.

   counterparty
       The counterparty of a channel is the other participant of the channel that is not ourselves.

   preimage
   secret
       The preimage, what we call the secret in Raiden, is 32 bytes of random cryptographically secure data whose keccak hash ends up being the :term:`hashlock`.
