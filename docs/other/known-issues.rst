Known Issues
============

Below you find a non-exhaustive list of known issues, which you should be aware of while using the current version of the software. 
Most of these issues are not Raiden specific, but rather apply to all blockchain applications.

-  **Compromised user system:** If the system of the user is compromised
   and accessed by an attacker or if a malicious application is running,
   then the write-ahead logging (WAL) could be accessed and valuable
   information leaked through it, since the WAL is not yet encrypted as
   such: `raiden-network/raiden#579 <https://github.com/raiden-network/raiden/issues/579>`__
-  **Disk Full:** The client does not properly handle the cases where
   the user’s disk may be full. This could lead to a loss of data due to
   the Raiden node crashing. In the future, we want to handle the
   detection of a full disk and gracefully quit the app:
   `raiden-network/raiden#675
   <https://github.com/raiden-network/raiden/issues/675>`__
-  **Blockchain Congestion:** If the blockchain is congested and there
   is no space for the Raiden node to submit transactions on-chain, the
   client could end up being unable to settle the channel on-chain. The
   development of a gas slot based settlement timeout definition has
   been suggested in order to address blockchain congestion:
   `raiden-network/raiden#383 <https://github.com/raiden-network/raiden/issues/383>`__
-  **Chain reorganizations:** The client used to have an issue with edge
   cases of chain reorganizations. These issues have been hot fixed by
   only polling events that are confirmed for 5 blocks. Same applies to
   processing transactions, which are assumed to be valid only after a
   confirmation period of 5 blocks. This results in 15 blocks wait time
   for opening a channel (three on-chain transactions).


**Database Upgrades**
---------------------

The database layout can change between versions. For **patch** and **minor**
change releases, Raiden will do automatic upgrades in the background, as soon as
you start the client with the new version. Your old database will always be kept
as a backup.

However, for **major** change releases, this may not always be possible. If the
client tells you, that the database migration was not possible, you are left with
two options:

- to recover all allocated funds, you should run the previous version of Raiden and
  **close** and **settle** all channels. Afterwards you can move your old database directory
  out of the way and join the network again with the same Ethereum keystore file.

- if there are no funds worth recovering, you can also simply start over with a new
  Ethereum keystore file and
  :ref:`start over <running_raiden>`.
  This should be true for all usage on testnet and in cases where your channel balances
  are very low on mainnet. Don't hesitate to
  `ask for help <https://discord.com/invite/nSQDQBq5FC>`__!
