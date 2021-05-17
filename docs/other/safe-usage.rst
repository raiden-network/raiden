Safe Usage
==========

**Important security notes for usage**
--------------------------------------

.. warning::

   Always keep in mind: Despite the fact that
   Alderaan is a lot more mature and reliable than Red Eyes, it is still a
   beta release. Please make sure to follow the below security notes and
   system requirements to avoid increasing the risk of losing funds. Note
   that the loss of tokens could happen even if you follow these
   guidelines.

-  **Ethereum node in sync and running reliably:** Ensure that layer 1
   works reliably. This means that you have to have an Ethereum node,
   either Geth or OpenEthereum, that is synced and working reliably. If there
   are any problems or bugs on the client then Raiden can not work
   reliably.
-  **Ethereum client always online:** Make sure that your Ethereum
   client is always online during operation of a Raiden node. As stated
   above, you can safely go offline if channel monitoring is enabled,
   but in order to use the Raiden nodes for doing transfers you have to
   have an online and synced Ethereum node, too. We recommend running it
   inside a monitor which will restart it if, for some reason, it
   crashes.
-  **Ethereum Client can not be changed:** Swapping the Ethereum client
   while transactions are not mined is considered unsafe. We recommend
   avoiding switching Ethereum clients once the Raiden node is running.
-  **Raiden online for operations:** Currently all nodes participating
   in a transfer need to be online in order for a transfer to be carried
   out. Hence, make sure that your Raiden node is always working, your
   network connection is stable and that the Raiden node is always
   online. As mentioned above, if a node has monitoring enabled it is
   safe to shut it down, but it will not be able to receive, mediate or
   send transfers while offline.
-  **Unique account for Raiden:** Raiden requires you to have a specific
   Ethereum account solely dedicated to Raiden. Creating any manual
   transaction with the Ethereum account that Raiden uses, while the
   Raiden client is running, can result in undefined behaviour. It is,
   however, safe to do manual transactions with the account if Raiden is
   not running.
-  **Raiden account has sufficient ETH:** Raiden will try to warn you if
   there is not enough ETH in your Raiden account in order to maintain
   your current open channels and allow them to go through their entire
   cycle. However, it is your job to refill your account with ETH and to
   make sure it is filled sufficiently once warned.
-  **Raiden account has sufficient UserDeposit:** If you are using
   pathfinding or monitoring service, you will pay for using these with
   IOUs through the UserDeposit smart contract. This deposit is done in
   RDN and if the user deposit does not have a sufficient balance, the
   Raiden services will not kick in, since they are not getting paid.
-  **Do not transfer too small amounts for mediated transfers:**
   Currently the Raiden client cancels payments that would require more
   than 20% of the transferred amount in fee costs. This means that the
   transferred amount has to be big enough, so that the fees do not
   surpass 20% of the transferred amount. This results in the following
   minimum amounts for the token networks when mediation is used:

   -  DAI: Min **0.00001 DAI**
   -  WETH: Min **Min 0.0000001 WETH**

-  **Persistency of local DB:** Your local state database is located at
   ~/.raiden. This data should not be deleted by the user or tampered
   with in any way. Frequent backups are recommended. Deleting this
   directory can result in a loss of funds.
-  **Never expose the Raiden REST API to the public:** For Raiden’s
   operation, the client needs to be able to sign transactions at any
   point in time. Therefore you should never expose the Raiden Rest API
   to the public. Be very careful when changing the –rpc and
   –rpccorsdomain values.
-  **Be patient:** Do not mash buttons in the webUI and do not shut down
   the client while on-chain transactions are on the fly and have not
   yet been confirmed.
