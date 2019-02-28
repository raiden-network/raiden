=========
Changelog
=========

* :bug:`3567` Properly check handling offline partners
* :feature:`2436` Add an API endpoint to list pending transfers
* :bug:`3475` Properly check async_result in rest api payments
* :feature:`3318` allow secret and/or hash with payment request
* :feature:`3425` Update raiden-contracts package to version 0.9.0

* :release:`0.100.2 <2019-02-21>`
* :bug:`3528` Do not crash raiden if a LockExpired message with invalid channel identifier is received.
* :bug:`3529` Do not crash raiden if a SecretRequest message with invalid channel identifier is received.

* :release:`0.100.2-rc4 <2019-02-04>`
* :feature:`3317` Return the secretHash and the Secret as part of payment response
* :bug:`3380` Connection manager no longer attempts deposit if per partner funds are zero.
* :bug:`3369` Fix high CPU usage when the raiden node is idle.
* :feature:`-` Set python 3.7 as a minimum python version requirement to run Raiden.
* :bug:`2974` Alarm task is not longer blocking until transactions are mined.
* :feature:`2793` Faster restarts, transactions are sent in parallel on restarts.

* :release:`0.100.2-rc3 <2019-01-25>`
* :feature:`-` Update WebUI to version 0.8.0 https://github.com/raiden-network/webui/releases/tag/v0.8.0
* :feature:`3236` Add backwards-compatible PFS integration in the routing layer
* :bug:`3196` Proper fix for the bug that caused not finding locksroot in the DB during unlock
* :feature:`2988` If estimateGas returns failure don't send a transaction.

* :release:`0.100.2-rc2 <2019-01-11>`
* :feature:`-` Update WebUI to version 0.7.1 https://github.com/raiden-network/webui/releases/tag/v0.7.1
* :bug:`3257` Requesting the channel list with a token address and not a partner address via the API should no longer cause a 500 server error.


* :release:`0.100.2-rc1 <2019-01-04>`
* :feature:`3217` If channel is already updated onchain don't call updateNonClosingBalanceProof.
* :bug:`3216` If coming online after partner closed channel don't try to send updateNonClosingBalanceProof twice and crash Raiden.
* :bug:`3211` If using parity and getting the already imported error, attempt to handle it and not crash the client.
* :bug:`3121` If the same payment identifier is reused avoid a specific race condition that can crash Raiden.
* :bug:`3201` Workaround for gas price strategy crashing Raiden with an Infura ethereum node.
* :bug:`3190` Prevents removal of initiator task when one of the transfers is expired.

* :release:`0.100.1 <2018-12-21>`
* :bug:`3171` Do not crash raiden if the Matrix server is offline when joining a discovery room.
* :bug:`3196` If our partner updates onchain with earlier balance proof find the event in the DB and properly perform the unlock onchain.
* :bug:`3193` Channel balance shown to the user now takes locked amount into account.
* :bug:`3183` If as initiator our nodes receives a RefundTransfer then do not delete the payment task at the lock expiration block but wait for a LockExpired message. Solves one hanging transfer case.
* :bug:`3179` Properly process a SendRefundTransfer event if it's the last one before settlement and not crash the client.
* :bug:`3175` If Github checking of latest version returns unexpected response do not let Raiden crash.
* :bug:`3170` If the same refund transfer is received multiple times, the mediator state machine will reject subsequent ones rather than clearing up the mediator task.
* :bug:`3146` If a refund transfer is received and there are no other routes, keep the payment task so that the channel does not hang when mediator sends a LockExpired.

* :release:`0.19.0 <2018-12-14>`
* :bug:`3153` If a non-contract address is given for token_address in the channel open REST API call, the client no longer crashes.
* :bug:`3152` If the onchain unlock has already been mined when we try to send the transaction don't crash Raiden.
* :feature:`3157` Change REST api version prefix from 1 to v1.
* :bug:`3135` In development mode if more than 100 * (10^18) tokens are deposited then raiden no longer crashes.

* :release:`0.18.1 <2018-12-07>`
* :bug:`2779` Fixes a long standing bug that could cause payments to hang indefinitely.
* :bug:`3103` Fixes a bug in matrix which prevented retries of messages.
* :bug:`3094` Raiden will now properly return payment failure and no longer hang if a payment times out due to a lock expiration.
* :bug:`3093` Getting raiden payment history will no longer crash raiden for failed sent payment events.

* :release:`0.18.0 <2018-11-30>`
* :bug:`3091` Client will no longer accept secret of 0x0 or secrethash keccak(0x0).
* :bug:`3054` Client will now reject any signatures with ``v`` not in (0, 1, 27, 28)
* :bug:`3046` Sync with the matrix server using the last known sync token. This solves the issue of missing messages during restart as previously only the last 10 were fetched.

* :release:`0.17.0 <2018-11-16>`
* :bug:`3035` Registering a token twice should now return a proper error.
* :bug:`3013` Encode all integers before saving to the sqlite database
* :bug:`3022` Reject REST API channel opening with an error if there is not enough token balance for the initial deposit.
* :bug:`2932` Node will no longer crash if it mediated a transfer and the channel cycle for mediation has completed.
* :bug:`3001` Don't delete payment task when receiving invalid secret request.
* :bug:`2931` Fixes serialization of state changes for refund transfers, allowing it to be used for unlocks.

* :release:`0.16.0 <2018-11-09>`
* :bug:`2963` Fixes an overflow issue with the hint of the join network dialog.
* :bug:`2973` Introduce special handling of infura endpoints so that the old getTransactionCount is used.
* :feature:`2946` Do not show full block information in the INFO logging message.
* :bug:`2921` Properly estimate gas cost of transactions so that we have a more reasonable minimal amount of ETH required to run Raiden.
* :feature:`2962` Check that the ethereum node has all required json rpc interfaces enabled when Raiden starts. If not fail with a proper error.
* :bug:`2951` Fallback to eth_getTransactionCount if there is no api to get the next available nonce.
* :bug:`2934` Don't send unecessary register secret transactions.
* :bug:`2938` Don't cleanup mediator if the transfer could not be forwarded. Could lead to stuck channels.
* :bug:`2918` Fixed a synchronization problem, where a node would send invalid balance proofs.
* :bug:`2923` Fix a race with multiple calls circumventing the gas reserve check.

* :release:`0.15.1 <2018-11-03>`
* :bug:`2933` Raiden can now recover from crashes/restarts when there are pending onchain transactions.

* :release:`0.15.0 <2018-10-27>`
* :bug:`2905` Mediator task must wait for the expired message, not just for the lock to expire, otherwise the channel will be unsychronized.
* :feature:`2909` Add explicit flag `--unrecoverable-error-should-crash` to control UnrecoverableError crashing behaviour.
* :bug:`2894` Raiden will no longer miss confirmation blocks at restart and will emit the block state change only for confirmed blocks.
* :feature:`2857` Respect the ``--environment-type`` for private chain setup.
* :feature:`2858` Changed contract address argument names to be consistent with the names of the contracts in the contracts repository.

* :release:`0.14.0 <2018-10-20>`
* :bug:`2845` Properly update local state balance proof during a lock expiration.
* :bug:`2835` Incorrectly accepting a ``RemoveLockExpired`` is no longer possible
* :feature:`2752` Renamed ``--network-type`` cli option to ``--environment-type``.
* :bug:`2836` Contract version check now works for any deployed contract version.
* :bug:`2449` Only polling events from confirmed blocks to prevent conflicts with reorgs.
* :bug:`2827` Fixed a typo in the handle_secretrequest function.
* :bug:`2813` Fixed swapped message and payment id, which caused problems on node restart.
* :bug:`2794` UnlockPartialProofState does no longer raise AttributeError when accessing lockhash.
* :bug:`2664` Raiden node will now wait for 5 block confirmations before processing a given transaction.

* :release:`0.13.1 <2018-10-15>`
* :bug:`2784` Raiden node is no longer left with a partial update if it crashes during polling.
* :bug:`2776` Properly include per chain contract json data in the created binaries

* :release:`0.13.0 <2018-10-12>`
* :feature:`2764` Support pre-deployed contracts on Kovan and Rinkeby testnets
* :bug:`2746` Refuse to process a payment with an identifier already in use for another payment, and return a 409 Conflict in that case.
* :bug:`2662` Fix wrong deserialization of snapshots in special cases.
* :bug:`2730` Refuse to send a transfer and ignore it during receiving, if its secret is already registered on-chain.
* :feature:`2713` Added the protocol version in the Ping message.
* :feature:`2708` Add `--showconfig` CLI flag which dumps all configuration values that will control Raiden behavior.
* :bug:`2720` A lock expired message must be considered invalid if the block in which the lock expired has not been confirmed.

* :release:`0.12.0 <2018-10-05>`
* :feature:`2699` Add ``/channels/<token_address>`` REST-API endpoint to query all node's channels for a specific token.
* :feature:`2568` Validate the state changes for the Delivered and Processed sender.
* :bug:`2567` Increase default channel reveal timeout to 50 blocks.
* :bug:`2676` Return an error if an invalid ``joinable_funds_target`` value is provided to the connect endpoint.
* :bug:`2655` Raiden node will now properly crash if communication with the ethereum node is lost.
* :bug:`2630` If a smaller deposit than ``total_deposit`` is given to the deposit RPC call then return 409 Conflict and not 200 OK.

* :release:`0.11.0 <2018-09-28>`
* :bug:`2631` Prevent excessive state replay on restart
* :bug:`2566` Warn the user about older existing database versions
* :bug:`2609` Allow numeric network ids in the config file
* :bug:`2603` Prevent crash in case of invalid Matrix server response
* :bug:`2602` On-chain secret reveal forces off-chain reveal
* :feature:`2600` Improve logging for on-chain transactions
* :bug:`2577` Small logging improvements
* :bug:`2535` Registering a secret on-chain for a locked transfer is now checked if it was received before the lock has expired.

* :release:`0.10.0 <2018-09-21>`
* :bug:`2515` Adds validation for settle timeout against reveal timeout when opening a channel from the webui.
* :feature:`2517` Increase the time a notification stays visible on the webui.
* :feature:`2470` Add a main/test network switch enabling or disabling specific functionality depending on the network type.
* :bug:`2512` Add descending order by block_number as default for blockchain events on webui.
* :bug:`2507` Fix a security issue where an attacker could eavesdrop Matrix communications between two nodes in private rooms
* :bug:`2501` Adds a matrix.private_rooms config to communicate only through private rooms in Matrix
* :bug:`2449` Fix a race condition when handling channel close events.
* :bug:`2414` If partner uses our old balance proof on-chain, the raiden client will now recover it from the WAL and properly use it on-chain.

* :release:`0.9.0 <2018-09-14>`
* :feature:`2287` Internal events now have timestamps.
* :feature:`2307` Matrix discovery rooms now are decentralized, aliased and shared by all servers in the federation
* :bug:`2461` For received payments events filter based on the initiator.
* :feature:`2252` Adds payment history page to the webui.
* :bug:`2367` Token network selection dropdown will not filter out not connected networks.
* :bug:`2453` Connection manager will no longer be stuck if there are no available channel partners
* :bug:`2437` Fix a bug where neighbors couldn't communicate through matrix after restart
* :bug:`2370` Fixes a few issues with the token amount input.
* :bug:`2439` Return properly filtered results from the API payments event endpoint
* :bug:`2419` Fix Matrix transport crash due to inability to decode events
* :bug:`2427` Fix a bug crashing the client when an unlock event for our address is seen on the chain
* :bug:`2431` Do not crash on recoverable errors during settlement
* :feature:`1473` Add gas price strategies that adapt the gas price to the network conditions.
* :feature:`2460` Pinned depedencies versions, builds are now reproducible and build artifacts won't break because of downstream dependencies.

* :release:`0.8.0 <2018-09-07>`
* :feature:`1894` We now start having nightly releases found here: https://raiden-nightlies.ams3.digitaloceanspaces.com/index.html
* :bug:`2373` Include events for received payments in the payment events API endpoint.
* :feature:`862` Switch WAL serialization format to JSON in order to facilitate for WAL upgradability.
* :feature:`2363` Add copy functionality for addresses shown on the webui.
* :bug:`2356` Create a new database per token network registry.
* :bug:`2362` Renamed wallet to tokens in the webui.
* :bug:`2291` Adds EIP55 address validation to webui address inputs.
* :bug:`2283` Fix API server Internal server error at token deposits.
* :bug:`2336` Fixes webui wallet page not loading data due to error.
* :feature:`2340` Add ``--accept-disclaimer`` argument to bypass the experimental software disclaimer.

* :release:`0.7.0 <2018-08-31>`
* :feature:`2296` Gracefully handle malformed messages
* :feature:`2251` Add webui support for switching token input between decimal and integer values.
* :bug:`2293` Initiator had the payment and message identifiers swapped.
* :bug:`2275` Adds scientific notation for really small fractions when displaying balances.
* :bug:`2282` Fixes internal webui error that would not propagate channel updates.
* :bug:`2284` Fixes balance notifications showing for wrong channels.
* :feature:`2285` Request user acknowledgement for the experimental software disclaimer.
* :bug:`2277` Fixes sorting by balance for tokens and channels.
* :bug:`2278` Fixes leave network button request.
* :feature:`2225` Using a constant expiration for lock, making sure that on-chain unlocks are atomic.
* :bug:`2264` Notification fonts are now aligned with the rest of the WebUI.
* :bug:`2170` Removed block number from internal events and rearranged REST API debug endpoints

* :release:`0.6.0 <2018-08-24>`
* :feature:`2034` Update WebUI's design
* :feature:`2192` Show notification on the WebUI when transfer is received or when channel is opened
* :feature:`2134` Database is now versioned and the DB directory path now uses that version
* :feature:`2253` Make addresses in REST logging user readable
* :bug:`2198` Fix building of the WebUI in the linux bundle.
* :bug:`2176` Expose total_deposit in the Rest API and fix depositing in the WebUI
* :bug:`2233` Fix MatrixTransport exception for invalid user displayname
* :bug:`2197` WebUI now handles token decimals

* :release:`0.5.1 <2018-08-17>`
* :feature:`1898` Improve the event formatting in the REST API
* :feature:`439` Limit the number of pending transfers per channel.
* :bug:`2164` Update echo node to work with the new endpoint for channel history
* :bug:`2111` Correctly update network graph for non-participating channels

* :release:`0.5.0 <2018-08-10>`
* :bug:`2149` Don't crash if reusing same payment identifier for a payment
* :feature:`2090` Rename transfers to payments in the webui.
* :feature:`682` Store a Snapshot of WAL state as recovery optimization.
* :bug:`2125` Show proper error message for invalid tokens on ``/connections``.
* :feature:`1949` Add an endpoint to query the payment history.
* :bug:`2027` Raiden should now be able to connect to Infura.
* :feature:`2084` Rename the ``/transfers/`` endpoint to ``/payments/``.
* :feature:`1998` Add a strategy to make sure that the account Raiden runs on always has enough balance to settle all channels. No new channels can be openend when no sufficient balance for the whole channel lifecycle is available.
* :feature:`1950` Breaking change: Better transaction handling on restart. This change breaks binary compatibility with the previous WAL.

* :release:`0.4.2 <2018-08-02>`
* :bug:`2004` Show a webui error when JSON-RPC requests fail.
* :bug:`2039` Return error for negative deposits via REST API
* :feature:`2011` Add a ``--disable-debug-logfile`` argument to disable the always on debug file if required by the user.
* :bug:`1821` Show a better error message when channel creation fails.
* :bug:`1817` Change the webui error message when the token registration fails.
* :feature:`1844` Log debug output to a file to make debugging of problems easier.
* :bug:`1996` Providing contracts addresses via the CLI that either have no code or contain unexpected code will now result in an error and not crash Raiden.
* :bug:`1994` Starting Raiden with a corrupt database will now throw a proper error instead of crashing with an exception.

* :release:`0.4.1 <2018-07-27>`
* :bug:`1879` Leaving a token network should now work. Also removed the ``only_receiving`` parameter from the leave endpoint
* :bug:`1897` Limit number of concurrent matrix connections so that raiden client does not crash.
* :bug:`1976` Remove the ability to removedb. User should not be able to easily delete local state.
* :feature:`1825` Added periodical update notification and security releases checks.
* :bug:`1883` Properly update menu state when channel state changes on webui
* :bug:`1969` Return E409 if negative ``initial_funds`` are given to the connect endpoint
* :bug:`1960` Return E409 when trying to open a channel for a token that is not registered
* :bug:`1916` Return E409 on two concurrent conflicting channel deposits
* :bug:`1869` Various matrix improvements. Prevent DOS attacks, and race conditions that caused client crashes. Require peers to be present to send message to them. Improves user discovery across Matrix federation.
* :bug:`1902` Check for ethnode connection at start and print proper error if Raiden can not connect
* :bug:`1911` The syncing message is now printed properly and does not repeat across the screen
* :bug:`1899` Print proper error without throwing exception if no accounts are found in the keystore
* :bug:`1975` Fix balance hash generation for zero transfers and empty locksroot

* :release:`0.4.0 <2018-07-19>`
* :feature:`-` Considerable codebase refactoring.
* :feature:`-` New Matrix transport protocol.
* :feature:`-` Smart contracts refactoring for readability, gas costs and new features.
* :feature:`-` Restartability in case of a proper shutdown of the Raiden node.
* :feature:`1518` Update installation docs with Homebrew tap and update Homebrew formula on release.
* :feature:`1195` Improve AccountManager error handling if keyfile is invalid.
* :bug:`1237` Inform the user if geth binary is missing during raiden smoketest.
* :feature:`1328` Use separate database directory per network id. This is a breaking change. You will need to copy your data from the previous directory to the new network id subdirectory.

* :release:`0.3.0 <2018-02-22>`
* :bug:`1273` Don't crash when using the ``--nat=ext:IP`` command line option.
* :bug:`1217` Correctly decode network events in the REST API.
* :bug:`1224` Fix internal server error on REST endpoint ``/events/tokens/`` for non-existing tokens.
* :bug:`1261` REST API now returns json error for invalid endpoints.
* :feature:`1230` Unless specifically provided gas price and gas limit are now dynamically calculated from the ``eth_gasPrice()`` and latest blocks limit respectively.
* :feature:`87` Update raiden to use Python 3 and the latest version of pyethereum.
* :feature:`1015` Added macOS compatibility and binary releases.
* :feature:`1093` Reconnect raiden to ethereum node after disconnect.
* :bug:`1138` REST and Python API close did not work if a transfer was made.
* :feature:`1097` Added ``--gas-price`` command line option.
* :feature:`1038` Introduce an upper limit for the ``settle_timeout`` attribute of the netting channel.
* :bug:`1044` Rename ``/connection`` API endpoint to ``/connections`` for consistency.
* :bug:`1049` Make raiden byzantium compatible by no longer relying on ``estimateGas``.
* :feature:`507` Making python's channels crash resilient (recoverable). Note, this is a breaking change, the serialization format of channel objects changed to a WAL compatible representation.
* :feature:`1037` Add ``show_default`` to CLI options.
* :feature:`670` Block raiden startup until ethereum node is fully synchronized.
* :feature:`1010` Add ``amount`` and ``target`` to ``EventTransferSentSuccess`` event.
* :feature:`1022` Include an ``errors`` field in all unsuccessful API responses.
* :bug:`450` Removed ``block_number`` from contracts events, using block_number from block on which it was mined.
* :bug:`870` User selectable NAT traversal.
* :feature:`921` Add ``/api/1/connection`` API endpoint returning information about all connected token networks.
* :bug:`1011` Remove ``settled`` attribute from the NettingChannel smart contract.

* :release:`0.1.0 <2017-09-12>`
* :feature:`-`  This is the `Raiden Developer Preview <https://github.com/raiden-network/raiden/releases/tag/v0.1.0>`_ release. Introduces a raiden test network on ropsten, the API and all the basic functionality required to use Raiden in Dapps. For more information read the `blog post <https://medium.com/@raiden_network/raiden-network-developer-preview-dad83ec3fc23>`_ or the `documentation of v0.1.0 <http://raiden-network.readthedocs.io/en/v0.1.0/>`_.
