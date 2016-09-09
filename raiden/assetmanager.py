# -*- coding: utf8 -*-
from collections import defaultdict

from ethereum import slogging
from ethereum.abi import ContractTranslator
from ethereum.utils import sha3

from raiden.channel import Channel, ChannelEndState, ChannelExternalState
from raiden.blockchain.abi import NETTING_CHANNEL_ABI
from raiden.transfermanager import TransferManager
from raiden.messages import Secret
from raiden.tasks import LogListenerTask
from raiden.utils import isaddress, pex

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name


class AssetManager(object):
    """ Manages netting contracts for a given asset. """

    def __init__(self, raiden, asset_address, channel_manager_address, channel_graph):
        """
        Args:
            raiden (RaidenService): a node's service
            asset_address (bin): the asset address managed by this instance
            channel_manager_address (bin): The channel manager address.
            channelgraph (networkx.Graph): a graph representing the raiden network
        """
        if not isaddress(asset_address):
            raise ValueError('asset_address must be a valid address')

        self.partneraddress_channel = dict()  #: maps the partner address to the channel instance
        self.address_channel = dict()  #: maps the channel address to the channel instance
        self.hashlock_channel = defaultdict(list)  #: channels that are waiting on the conditional lock

        self.asset_address = asset_address
        self.channel_manager_address = channel_manager_address
        self.channelgraph = channel_graph
        self.raiden = raiden

        transfermanager = TransferManager(self)
        self.transfermanager = transfermanager

    def has_path(self, source, target):
        """ True if there is a path from `source` to `target`. """
        return self.channelgraph.has_path(source, target)

    def get_channel_by_partner_address(self, partner_address_bin):
        """ Return the channel with `partner_address_bin`.

        Raises:
            KeyError: If there is no channel with partner_address_bin.
        """
        return self.partneraddress_channel[partner_address_bin]

    def get_channel_by_contract_address(self, netting_channel_address_bin):
        """ Return the channel with `netting_channel_address_bin`.

        Raises:
            KeyError: If there is no channel with netting_channel_address_bin.
        """
        return self.address_channel[netting_channel_address_bin]

    def register_channel_by_address(self, netting_channel_address_bin, reveal_timeout):
        """ Register a deployed channel.

        Args:
            netting_channel_address_bin (bin): The netting contract address.
            reveal_timeout (int): Minimum number of blocks required by this
                node to see a secret.

        Raises:
            ValueError: If raiden.address is not one of the participants in the
                netting channel.
        """
        netting_channel = self.raiden.chain.netting_channel(netting_channel_address_bin)
        self.register_channel(netting_channel, reveal_timeout)

    def register_channel(self, netting_channel, reveal_timeout):
        """ Register a new channel.

        Args:
            netting_channel (network.rpc.client.NettingChannel): The netting channel proxy.
            reveal_timeout (int): Minimum number of blocks required by this
                node to see a secret.

        Raises:
            ValueError: If raiden.address is not one of the participants in the
                netting channel.
        """
        translator = ContractTranslator(NETTING_CHANNEL_ABI)

        # Race condition:
        # - If the filter is installed after the call to `details` a deposit
        # could be missed in the meantime, to avoid this we first install the
        # filter listener and then call `deposit`.
        # - Because of the above strategy a `deposit` event could be handled
        # twice, for this reason we must not use `deposit` in the events but
        # the resulting `balance`.

        task_name = 'ChannelNewBalance {}'.format(pex(netting_channel.address))
        newbalance = netting_channel.channelnewbalance_filter()
        newbalance_listener = LogListenerTask(
            task_name,
            newbalance,
            self.raiden.on_event,
            translator,
        )

        task_name = 'ChannelSecretRevelead {}'.format(pex(netting_channel.address))
        secretrevealed = netting_channel.channelsecretrevealed_filter()
        secretrevealed_listener = LogListenerTask(
            task_name,
            secretrevealed,
            self.raiden.on_event,
            translator,
        )

        task_name = 'ChannelClosed {}'.format(pex(netting_channel.address))
        close = netting_channel.channelclosed_filter()
        close_listener = LogListenerTask(
            task_name,
            close,
            self.raiden.on_event,
            translator,
        )

        task_name = 'ChannelSettled {}'.format(pex(netting_channel.address))
        settled = netting_channel.channelsettled_filter()
        settled_listener = LogListenerTask(
            task_name,
            settled,
            self.raiden.on_event,
            translator,
        )

        channel_details = netting_channel.detail(self.raiden.address)
        our_state = ChannelEndState(
            channel_details['our_address'],
            channel_details['our_balance'],
        )
        partner_state = ChannelEndState(
            channel_details['partner_address'],
            channel_details['partner_balance'],
        )

        external_state = ChannelExternalState(
            self.raiden.alarm.register_callback,
            self.register_channel_for_hashlock,
            self.raiden.chain.block_number,
            netting_channel,
        )

        channel = Channel(
            our_state,
            partner_state,
            external_state,

            self.asset_address,
            reveal_timeout,
            channel_details['settle_timeout'],
        )

        self.partneraddress_channel[partner_state.address] = channel
        self.address_channel[netting_channel.address] = channel

        self.channelgraph.add_path(
            channel_details['our_address'],
            channel_details['partner_address'],
        )

        newbalance_listener.start()
        secretrevealed_listener.start()
        close_listener.start()
        settled_listener.start()

        self.raiden.event_listeners.append(newbalance_listener)
        self.raiden.event_listeners.append(secretrevealed_listener)
        self.raiden.event_listeners.append(close_listener)
        self.raiden.event_listeners.append(settled_listener)

    def register_channel_for_hashlock(self, channel, hashlock):
        channels_registered = self.hashlock_channel[hashlock]

        if channel not in channels_registered:
            channels_registered.append(channel)

    def handle_secret(self, secret):
        """ Handle a secret that could be received from a Secret message or a
        ChannelSecretRevealed event.
        """
        hashlock = sha3(secret)
        channels_reveal = self.hashlock_channel[hashlock]

        secret_message = Secret(secret)
        self.raiden.sign(secret_message)

        while channels_reveal:
            reveal_to = channels_reveal.pop()

            # When a secret is revealed a message could be in-transit
            # containing the older lockroot, for this reason the recipient
            # cannot update it's locksroot at the moment a secret was revealed.
            #
            # The protocol is to register the secret so that it can compute a
            # proof of balance, if necessary, forward the secret to the sender
            # and wait for the update from it. It's the sender duty to order
            # the current in-transit (and possible the transfers in queue)
            # transfers and the secret/locksroot update.
            #
            # The channel and it's queue must be changed in sync, a transfer
            # must not be created and while we update the balance_proof.

            # critical read/write section
            # (relying on the GIL and non-blocking apis instead of an explicit
            # lock).

            # we are the sender, so we can claim the lock/update the locksroot
            # and add the update message into the end of the message queue, all
            # the messages will remain consistent (including the messages
            # in-transit and the ones that are already in the queue)
            if reveal_to.partner_state.balance_proof.is_pending(hashlock):
                reveal_to.claim_lock(secret)
                self.raiden.send_async(reveal_to.partner_state.address, secret_message)

            # we are the recipient, register the secret so that a balance proof
            # can be generate and reveal the secret to the sender. the asset
            # will be claimed once the secret is received from the sender in
            # the MediatedTransferTask
            elif reveal_to.our_state.balance_proof.is_pending(hashlock):
                reveal_to.register_secret(secret)
                self.raiden.send_async(reveal_to.partner_state.address, secret_message)

            else:
                log.error('No corresponding hashlock for the given secret.')
            # /critical read/write section

        # delete the list it wont ever be used again (unless we have a sha3
        # collision)
        del self.hashlock_channel[hashlock]

    def channel_isactive(self, partner_address):
        """ True if the channel with `partner_address` is open. """
        # TODO: check if the partner's network is alive
        return self.get_channel_by_partner_address(partner_address).isopen

    def get_best_routes(self, amount, target, lock_timeout=None):
        """ Yield a two-tuple (path, channel) that can be used to mediate the
        transfer. The result is ordered from the best to worst path.
        """
        available_paths = self.channelgraph.get_shortest_paths(
            self.raiden.address,
            target,
        )

        for path in available_paths:
            assert path[0] == self.raiden.address
            assert path[1] in self.partneraddress_channel
            assert path[-1] == target

            partner = path[1]
            channel = self.partneraddress_channel[partner]

            if not channel.isopen:
                log.info('channel {} - {} is close, ignoring'.format(pex(path[0]), pex(path[1])))
                continue

            # we can't intermediate the transfer if we don't have enough funds
            if amount > channel.distributable:
                log.info('channel {} - {} doesnt have enough funds [{}], ignoring'.format(
                    pex(path[0]),
                    pex(path[1]),
                    amount,
                ))
                continue

            # Our partner won't accept a locked transfer that can expire after
            # the settlement period, otherwise the secret could be revealed
            # after channel is settled and he would lose the asset, or before
            # the minimum required.
            if lock_timeout and not channel.reveal_timeout <= lock_timeout < channel.settle_timeout:
                log.info(
                    'lock_expiration is too large, channel/path cannot be used',
                    lock_timeout=lock_timeout,
                    reveal_timeout=channel.reveal_timeout,
                    settle_timeout=channel.settle_timeout,
                    nodeid=pex(path[0]),
                    partner=pex(path[1]),
                )
                continue

            yield (path, channel)
