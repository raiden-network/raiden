=========
Changelog
=========

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
