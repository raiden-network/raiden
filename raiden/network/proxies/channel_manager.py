# -*- coding: utf-8 -*-
import logging
from binascii import unhexlify

from ethereum import slogging

from raiden.blockchain.abi import (
    CONTRACT_MANAGER,
    CONTRACT_CHANNEL_MANAGER,
    EVENT_CHANNEL_NEW,
)
from raiden.constants import (
    NETTINGCHANNEL_SETTLE_TIMEOUT_MIN,
    NETTINGCHANNEL_SETTLE_TIMEOUT_MAX,
)
from raiden.network.rpc.filters import (
    new_filter,
    Filter,
)
from raiden.network.rpc.transactions import (
    check_transaction_threw,
    estimate_and_transact,
)
from raiden.exceptions import (
    AddressWithoutCode,
    DuplicatedChannelError,
    SamePeerAddress,
)
from raiden.settings import (
    DEFAULT_POLL_TIMEOUT,
)
from raiden.utils import (
    address_decoder,
    address_encoder,
    isaddress,
    pex,
    privatekey_to_address,
)

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name


class ChannelManager(object):
    def __init__(
            self,
            jsonrpc_client,
            manager_address,
            startgas,
            gasprice,
            poll_timeout=DEFAULT_POLL_TIMEOUT):
        # pylint: disable=too-many-arguments

        if not isaddress(manager_address):
            raise ValueError('manager_address must be a valid address')

        result = jsonrpc_client.call(
            'eth_getCode',
            address_encoder(manager_address),
            'latest',
        )

        if result == '0x':
            raise AddressWithoutCode('Channel manager address {} does not contain code'.format(
                address_encoder(manager_address),
            ))

        proxy = jsonrpc_client.new_contract_proxy(
            CONTRACT_MANAGER.get_abi(CONTRACT_CHANNEL_MANAGER),
            address_encoder(manager_address),
        )

        self.address = manager_address
        self.proxy = proxy
        self.client = jsonrpc_client
        self.startgas = startgas
        self.gasprice = gasprice
        self.poll_timeout = poll_timeout

    def token_address(self):
        """ Return the token of this manager. """
        return address_decoder(self.proxy.call('tokenAddress'))

    def new_netting_channel(self, peer1, peer2, settle_timeout):
        if not isaddress(peer1):
            raise ValueError('The peer1 must be a valid address')

        if not isaddress(peer2):
            raise ValueError('The peer2 must be a valid address')

        invalid_timeout = (
            settle_timeout < NETTINGCHANNEL_SETTLE_TIMEOUT_MIN or
            settle_timeout > NETTINGCHANNEL_SETTLE_TIMEOUT_MAX
        )
        if invalid_timeout:
            raise ValueError('settle_timeout must be in range [{}, {}]'.format(
                NETTINGCHANNEL_SETTLE_TIMEOUT_MIN, NETTINGCHANNEL_SETTLE_TIMEOUT_MAX
            ))

        if peer1 == peer2:
            raise SamePeerAddress('Peer1 and peer2 must not be equal')

        if privatekey_to_address(self.client.privkey) == peer1:
            other = peer2
        else:
            other = peer1

        transaction_hash = estimate_and_transact(
            self.proxy,
            'newChannel',
            self.startgas,
            self.gasprice,
            other,
            settle_timeout,
        )

        self.client.poll(unhexlify(transaction_hash), timeout=self.poll_timeout)

        if check_transaction_threw(self.client, transaction_hash):
            raise DuplicatedChannelError('Duplicated channel')

        netting_channel_results_encoded = self.proxy.call(
            'getChannelWith',
            other,
            startgas=self.startgas,
        )

        # address is at index 0
        netting_channel_address_encoded = netting_channel_results_encoded

        if not netting_channel_address_encoded:
            log.error('netting_channel_address failed', peer1=pex(peer1), peer2=pex(peer2))
            raise RuntimeError('netting_channel_address failed')

        netting_channel_address_bin = address_decoder(netting_channel_address_encoded)

        if log.isEnabledFor(logging.INFO):
            log.info(
                'new_netting_channel called',
                peer1=pex(peer1),
                peer2=pex(peer2),
                netting_channel=pex(netting_channel_address_bin),
            )

        return netting_channel_address_bin

    def channels_addresses(self):
        # for simplicity the smart contract return a shallow list where every
        # second item forms a tuple
        channel_flat_encoded = self.proxy.call(
            'getChannelsParticipants',
            startgas=self.startgas,
        )

        channel_flat = [
            address_decoder(channel)
            for channel in channel_flat_encoded
        ]

        # [a,b,c,d] -> [(a,b),(c,d)]
        channel_iter = iter(channel_flat)
        return zip(channel_iter, channel_iter)

    def channels_by_participant(self, participant_address):  # pylint: disable=invalid-name
        """ Return a list of channel address that `participant_address` is a participant. """
        address_list = self.proxy.call(
            'nettingContractsByAddress',
            participant_address,
            startgas=self.startgas,
        )

        return [
            address_decoder(address)
            for address in address_list
        ]

    def channelnew_filter(self, from_block=None, to_block=None):
        """ Install a new filter for ChannelNew events.

        Return:
            Filter: The filter instance.
        """
        topics = [CONTRACT_MANAGER.get_event_id(EVENT_CHANNEL_NEW)]

        channel_manager_address_bin = self.proxy.contract_address
        filter_id_raw = new_filter(
            self.client,
            channel_manager_address_bin,
            topics,
            from_block=from_block,
            to_block=to_block
        )

        return Filter(
            self.client,
            filter_id_raw,
        )
