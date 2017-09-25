=========
Changelog
=========

* :feature:`1038` Introduce an upper limit for the ``settle_timeout`` attribute of the netting channel
* :bug:`1044` Rename ``/connection`` API endpoint to ``/connections`` for consistency
* :bug: `1049` Make raiden byzantium compatible by no longer relying on ``estimateGas``.
* :feature: `507` Making python's channels crash resilient (recoverable). Note, this is a breaking change, the serialization format of channel objects changed to a WAL compatible representation.
* :feature:`1037` Add ``show_default`` to CLI options
* :feature:`670` Block raiden startup until ethereum node is fully synchronized.
* :feature:`1010` Add ``amount`` and ``target`` to ``EventTransferSentSuccess`` event
* :feature:`1022` Include an ``errors`` field in all unsuccessful API responses.
* :bug:`450` Removed ``block_number`` from contracts events, using block_number from block on which it was mined.
* :bug:`870` User selectable NAT traversal
* :feature:`921` Add ``/api/1/connection`` API endpoint returning information about all connected token networks.
* :bug:`1011` Remove ``settled`` attribute from the NettingChannel smart contract.

* :release:`0.1.0 <2017-09-12>`
* :feature:`-`  This is the `Raiden Developer Preview <https://github.com/raiden-network/raiden/releases/tag/v0.1.0>`_ release. Introduces a raiden test network on ropsten, the API and all the basic functionality required to use Raiden in Dapps. For more information read the `blog post <https://medium.com/@raiden_network/raiden-network-developer-preview-dad83ec3fc23>`_ or the `documentation of v0.1.0 <http://raiden-network.readthedocs.io/en/v0.1.0/>`_.
