Raiden Glossary
===============

.. glossary::
   :sorted:

   payer
       In a channel relationship between two raiden nodes the payer is the participant who sends a transfer.

   payee
       In a channel relationship between two raiden nodes the payee is the participant who receives a transfer

   initiator
       In a mediated transfer the initiator of the transfer is the raiden node which starts the transfer

   target
       In a mediated transfer the target is the raiden node for which the transfer sent by the initiator is intended

   DirectTransfer
       A direct transfer is a non-locked transfer, which means a transfer that does not rely on a lock to complete. Once they are sent they should be considered as completed.

   MediatedTransfer
       A mediated transfer is a hashlocked transfer between an initiator and a target propagated through nodes in the network.

   RefundTransfer
       A refund transfer is a special type of MediatedTransfer that is used when a node can no longer propagate a transfer and a routing backtrack needs to be done.

   reveal timeout
       The number of blocks in a channel allowed for learning about a secret being reveal through the blockchain and acting on it.
       
   netting channel
       The on-chain payment channel between two raiden nodes.

   settlement timeout
   settlement window
       The number of blocks after the closing of a channel within which the counterparty is able to call ``updateTransfer`` and show the transfers they received.

   merkletree root
   locksroot
       The root of the :ref:`merkle tree<merkletree-section>` which holds the hashes of all the locks in the channel.

   transferred amount
       The transferred amount is the total amount of token one participant of a netting channel has sent to his counterparty.

   channel capacity
       A channel's capacity is the sum of the total deposits of both its participants. It is also the sum of the channel participants :term:`net balance`.

   net balance
       The net balance :math:`B_n` of a channel participant :math:`P` is his total deposit :math:`P_d` along with the amount of token he received :math:`P_r` minus the amount :math:`P_s` of token he has sent. So :math:`B_n = P_d + P_r - P_s`

   locked balance
       The locked balance :math:`B_l` of a channel participant is the sum of the locked amount for all pending transfers :math:`T_p`. So :math:`B_l = \sum_{k=0}^{N-1} T_p` where :math:`N` is the number of pending transfers.

   available balance
       The available balance :math:`B_a` of a channel participant is :math:`B_a = B_n - B_l`.

   balance proof
       Balance proof is any kind of message we use in order to cryptographically prove to our counterparty (or them to us) that their balance has changed and that we have received a transfer. 

   hashlock
       A hashlock is the hashed secret that accompanis a locked message: ``sha3(secret``

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
       The preimage, what we call the secret in raiden, is 32 bytes of random cryptographically secure data whose keccak hash ends up being the :term:`hashlock`.
