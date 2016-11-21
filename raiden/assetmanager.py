# -*- coding: utf-8 -*-
import logging
from collections import defaultdict

from ethereum import slogging
from ethereum.abi import ContractTranslator
from ethereum.utils import sha3

from raiden.channel import Channel, ChannelEndState, ChannelExternalState
from raiden.blockchain.abi import NETTING_CHANNEL_ABI
from raiden.transfermanager import TransferManager
from raiden.messages import Secret, RevealSecret
from raiden.tasks import LogListenerTask
from raiden.utils import isaddress, pex

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name


class AssetManager(object):  # pylint: disable=too-many-instance-attributes
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

        # This is a map from a hashlock to a list of channels, the same
        # hashlock can be used in more than one AssetManager (for exchanges), a
        # channel should be removed from this list only when the lock is
        # released/withdrawed but not when the secret is registered.
        self.hashlock_channel = defaultdict(list)  #: channels waiting on the conditional lock

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
            ValueError:
                - If raiden.address is not one of the participants in the
                netting channel.
                - If the contract's settle_timeout is smaller than the
                reveal_timeout.
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
            ValueError:
                - If raiden.address is not one of the participants in the
                netting channel.
                - If the contract's settle_timeout is smaller than the
                reveal_timeout.
        """
        # pylint: disable=too-many-locals

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

    def register_secret(self, secret):
        """ Register the secret with the interested channels.

        Note:
            The channel needs to be registered with
            `register_channel_for_hashlock`.
        """
        hashlock = sha3(secret)
        revealsecret_message = RevealSecret(secret)
        self.raiden.sign(revealsecret_message)

        channels_list = self.hashlock_channel[hashlock]
        for channel in channels_list:
            channel.register_secret(secret)

            # This will potentially be executed multiple times and could suffer
            # from amplification, the protocol will ignore messages that were
            # already registered and send it only until a first Ack is
            # received.
            self.raiden.send_async(
                channel.partner_state.address,
                revealsecret_message,
            )

    def handle_secret(self, identifier, secret):
        """ Unlock locks, register the secret, and send Secret messages as
        necessary.

        This function will:
            - Unlock the locks created by this node and send a Secret message to
            the corresponding partner so that she can withdraw the asset.
            - Register the secret for the locks received and reveal the secret
            to the senders

        Note:
            The channel needs to be registered with
            `register_channel_for_hashlock`.
        """
        # handling the secret needs to:
        # - unlock the asset for all `forward_channel` (the current one
        #   and the ones that failed with a refund)
        # - send a message to each of the forward nodes allowing them
        #   to withdraw the asset
        # - register the secret for the `originating_channel` so that a
        #   proof can be made, if necessary
        # - reveal the secret to the `sender` node (otherwise we
        #   cannot withdraw the asset)
        hashlock = sha3(secret)
        self._secret(identifier, secret, None, hashlock)

    def handle_secretmessage(self, partner_secret_message):
        """ Unlock locks, register the secret, and send Secret messages as
        necessary.

        This function will:
            - Withdraw the lock from sender.
            - Unlock the locks created by this node and send a Secret message to
            the corresponding partner so that she can withdraw the asset.
            - Register the secret for the locks received and reveal the secret
            to the senders

        Note:
            The channel needs to be registered with
            `register_channel_for_hashlock`.
        """
        secret = partner_secret_message.secret
        identifier = partner_secret_message.identifier
        hashlock = sha3(secret)
        self._secret(identifier, secret, partner_secret_message, hashlock)

    def _secret(self, identifier, secret, partner_secret_message, hashlock):
        channels_list = self.hashlock_channel[hashlock]
        channels_to_remove = list()

        # Dont use the partner_secret_message.asset since it might not match with the
        # current asset manager
        our_secret_message = Secret(identifier, secret, self.asset_address)
        self.raiden.sign(our_secret_message)

        revealsecret_message = RevealSecret(secret)
        self.raiden.sign(revealsecret_message)

        for channel in channels_list:
            # critical read/write section
            # - the `release_lock` might raise if the `balance_proof` changes
            #   after the check
            # - a message created before the lock is release must be added in
            #   the message queue before `our_secret_message`
            # We are relying on the GIL and non-blocking apis instead of an
            # explicit lock.

            if channel.partner_state.balance_proof.is_unclaimed(hashlock):
                # we are the sender, so we can release the lock once the secret
                # is known and add the update message into the end of the
                # message queue, all the messages will remain consistent
                # (including the messages in-transit and the ones that are
                # already in the queue)
                channel.release_lock(secret)

                # notify our partner that our state is updated and it can
                # withdraw the asset
                self.raiden.send_async(channel.partner_state.address, our_secret_message)

                channels_to_remove.append(channel)

            # we are the recipient, we can only withdraw the asset if a secret
            # message is received from the correct sender and asset address, so
            # withdraw if a valid message is received otherwise register the
            # secret and reveal the secret to channel patner.
            if channel.our_state.balance_proof.is_unclaimed(hashlock):
                # partner_secret_message might be None
                if partner_secret_message:
                    valid_sender = partner_secret_message.sender == channel.partner_state.address
                    valid_asset = partner_secret_message.asset == channel.asset_address

                    if valid_sender and valid_asset:
                        channel.withdraw_lock(secret)
                        channels_to_remove.append(channel)
                    else:
                        # assume our partner does not know the secret and reveal it
                        channel.register_secret(secret)
                        self.raiden.send_async(channel.partner_state.address, revealsecret_message)
                else:
                    channel.register_secret(secret)
                    self.raiden.send_async(channel.partner_state.address, revealsecret_message)
            # /critical read/write section

        for channel in channels_to_remove:
            channels_list.remove(channel)

        # delete the list from defaultdict, it wont be used again
        if len(channels_list) == 0:
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

        # XXX: consider using multiple channels for a single transfer. Useful
        # for cases were the `amount` is larger than what is available
        # individually in any of the channels.
        #
        # One possible approach is to _not_ filter these channels based on the
        # distributable amount, but to sort them based on available balance and
        # let the task use as many as required to finish the transfer.

        for path in available_paths:
            assert path[0] == self.raiden.address
            assert path[1] in self.partneraddress_channel
            assert path[-1] == target

            partner = path[1]
            channel = self.partneraddress_channel[partner]

            if not channel.isopen:
                if log.isEnabledFor(logging.INFO):
                    log.info(
                        'channel %s - %s is close, ignoring',
                        pex(path[0]),
                        pex(path[1]),
                    )

                continue

            # we can't intermediate the transfer if we don't have enough funds
            if amount > channel.distributable:
                if log.isEnabledFor(logging.INFO):
                    log.info(
                        'channel %s - %s doesnt have enough funds [%s], ignoring',
                        pex(path[0]),
                        pex(path[1]),
                        amount,
                    )
                continue

            if lock_timeout:
                # Our partner wont accept a lock timeout that:
                # - is larger than the settle timeout, otherwise the lock's
                # secret could be release /after/ the channel is settled.
                # - is smaller than the reveal timeout, because that is the
                # minimum number of blocks required by the partner to learn the
                # secret.
                valid_timeout = channel.reveal_timeout <= lock_timeout < channel.settle_timeout

                if not valid_timeout and log.isEnabledFor(logging.INFO):
                    log.info(
                        'lock_expiration is too large, channel/path cannot be used',
                        lock_timeout=lock_timeout,
                        reveal_timeout=channel.reveal_timeout,
                        settle_timeout=channel.settle_timeout,
                        nodeid=pex(path[0]),
                        partner=pex(path[1]),
                    )

                # do not try the route since we know the transfer will be rejected.
                if not valid_timeout:
                    continue

            yield (path, channel)
