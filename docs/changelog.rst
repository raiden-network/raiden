=========
Changelog
=========

* :feature:`1518` Update installation docs with Homebrew tap and update Homebrew formula on release
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
