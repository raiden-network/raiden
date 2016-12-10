# -*- coding: utf-8 -*-
import gevent
import rlp
from ethereum import slogging
from ethereum import _solidity
from ethereum.transactions import Transaction
from ethereum.utils import denoms, int_to_big_endian, encode_hex, normalize_address
from pyethapp.jsonrpc import address_encoder, address_decoder, data_decoder, default_gasprice
from pyethapp.rpc_client import topic_encoder, JSONRPCClient

from raiden import messages
from raiden.utils import (
    get_contract_path,
    isaddress,
    pex,
    privatekey_to_address,
)
from raiden.blockchain.abi import (
    ASSETADDED_EVENTID,
    CHANNELCLOSED_EVENTID,
    CHANNEL_MANAGER_ABI,
    CHANNELNEWBALANCE_EVENTID,
    CHANNELNEW_EVENTID,
    CHANNELSECRETREVEALED_EVENTID,
    CHANNELSETTLED_EVENTID,
    ENDPOINT_REGISTRY_ABI,
    HUMAN_TOKEN_ABI,
    NETTING_CHANNEL_ABI,
    REGISTRY_ABI,
)

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name

GAS_LIMIT = 3141592  # Morden's gasLimit.
GAS_LIMIT_HEX = '0x' + int_to_big_endian(GAS_LIMIT).encode('hex')
GAS_PRICE = denoms.shannon * 20

DEFAULT_POLL_TIMEOUT = 60

solidity = _solidity.get_solidity()  # pylint: disable=invalid-name

# Coding standard for this module:
#
# - Be sure to reflect changes to this module in the test
#   implementations. [tests/utils/*_client.py]
# - Expose a synchronous interface by default
#   - poll for the transaction hash
#   - check if the proper events were emited
#   - use `call` and `transact` to interact with pyethapp.rpc_client proxies


def patch_send_transaction(client, nonce_offset=0):
    """Check if the remote supports pyethapp's extended jsonrpc spec for local tx signing.
    If not, replace the `send_transaction` method with a more generic one.
    """
    patch_necessary = False
    try:
        client.call('eth_nonce', encode_hex(client.sender), 'pending')
    except:
        patch_necessary = True

    def send_transaction(sender, to, value=0, data='', startgas=GAS_LIMIT,
                         gasprice=GAS_PRICE, nonce=None):
        """Custom implementation for `pyethapp.rpc_client.JSONRPCClient.send_transaction`.
        This is necessary to support other remotes that don't support pyethapp's extended specs.
        @see https://github.com/ethereum/pyethapp/blob/develop/pyethapp/rpc_client.py#L359
        """
        pending_transactions_hex = client.call(
            'eth_getTransactionCount',
            encode_hex(sender),
            'pending',
        )
        pending_transactions = int(pending_transactions_hex, 16)
        nonce = pending_transactions + nonce_offset

        tx = Transaction(nonce, gasprice, startgas, to, value, data)
        assert hasattr(client, 'privkey') and client.privkey
        tx.sign(client.privkey)
        result = client.call('eth_sendRawTransaction', rlp.encode(tx).encode('hex'))
        return result[2 if result.startswith('0x') else 0:]

    if patch_necessary:
        client.send_transaction = send_transaction


def new_filter(jsonrpc_client, contract_address, topics):
    """ Custom new filter implementation to handle bad encoding from geth rpc. """
    json_data = {
        'fromBlock': '',
        'toBlock': '',
        'address': address_encoder(normalize_address(contract_address)),
        'topics': [topic_encoder(topic) for topic in topics],
    }

    return jsonrpc_client.call('eth_newFilter', json_data)


def decode_topic(topic):
    return int(topic[2:], 16)


class BlockChainService(object):
    """ Exposes the blockchain's state through JSON-RPC. """
    # pylint: disable=too-many-instance-attributes,unused-argument

    def __init__(
            self,
            privatekey_bin,
            registry_address,
            host,
            port,
            poll_timeout=DEFAULT_POLL_TIMEOUT,
            **kwargs):

        self.address_asset = dict()
        self.address_discovery = dict()
        self.address_manager = dict()
        self.address_contract = dict()
        self.address_registry = dict()
        self.asset_manager = dict()

        # if this object becomes a problem for testing consider using one of
        # the mock blockchains
        jsonrpc_client = JSONRPCClient(
            privkey=privatekey_bin,
            host=host,
            port=port,
            print_communication=kwargs.get('print_communication', False),
        )
        patch_send_transaction(jsonrpc_client)

        self.client = jsonrpc_client
        self.private_key = privatekey_bin
        self.node_address = privatekey_to_address(privatekey_bin)
        self.poll_timeout = poll_timeout
        self.default_registry = self.registry(registry_address)

    def set_verbosity(self, level):
        if level:
            self.client.print_communication = True

    def block_number(self):
        return self.client.blocknumber()

    def next_block(self):
        target_block_number = self.block_number() + 1
        current_block = target_block_number

        while not current_block >= target_block_number:
            current_block = self.block_number()
            gevent.sleep(0.5)

        return current_block

    def asset(self, asset_address):
        """ Return a proxy to interact with an asset. """
        if asset_address not in self.address_asset:
            self.address_asset[asset_address] = Asset(
                self.client,
                asset_address,
                poll_timeout=self.poll_timeout,
            )

        return self.address_asset[asset_address]

    def discovery(self, discovery_address):
        """ Return a proxy to interact with the discovery. """
        if discovery_address not in self.address_discovery:
            self.address_discovery[discovery_address] = Discovery(
                self.client,
                discovery_address,
                poll_timeout=self.poll_timeout,
            )

        return self.address_discovery[discovery_address]

    def netting_channel(self, netting_channel_address):
        """ Return a proxy to interact with a NettingChannelContract. """
        if netting_channel_address not in self.address_contract:
            channel = NettingChannel(
                self.client,
                netting_channel_address,
                poll_timeout=self.poll_timeout,
            )
            self.address_contract[netting_channel_address] = channel

        return self.address_contract[netting_channel_address]

    def manager(self, manager_address):
        """ Return a proxy to interact with a ChannelManagerContract. """
        if manager_address not in self.address_manager:
            manager = ChannelManager(
                self.client,
                manager_address,
                poll_timeout=self.poll_timeout,
            )

            asset_address = manager.asset_address()

            self.asset_manager[asset_address] = manager
            self.address_manager[manager_address] = manager

        return self.address_manager[manager_address]

    def manager_by_asset(self, asset_address):
        """ Find the channel manager for `asset_address` and return a proxy to
        interact with it.
        """
        if asset_address not in self.asset_manager:
            asset = self.asset(asset_address)  # check that the asset exists
            manager_address = self.default_registry.manager_address_by_asset(asset.address)
            manager = ChannelManager(
                self.client,
                address_decoder(manager_address),
                poll_timeout=self.poll_timeout,
            )

            self.asset_manager[asset_address] = manager
            self.address_manager[manager_address] = manager

        return self.asset_manager[asset_address]

    def registry(self, registry_address):
        if registry_address not in self.address_registry:
            self.address_registry[registry_address] = Registry(
                self.client,
                registry_address,
                poll_timeout=self.poll_timeout,
            )

        return self.address_registry[registry_address]

    def uninstall_filter(self, filter_id_raw):
        self.client.call('eth_uninstallFilter', filter_id_raw)

    def deploy_contract(self, contract_name, contract_file, constructor_parameters=None):
        contract_path = get_contract_path(contract_file)
        contracts = _solidity.compile_file(contract_path, libraries=dict())

        log.info(
            'Deploying "%s" contract',
            contract_file,
        )

        proxy = self.client.deploy_solidity_contract(
            self.node_address,
            contract_name,
            contracts,
            dict(),
            constructor_parameters,
            gasprice=default_gasprice,
            timeout=self.poll_timeout,
        )
        return proxy.address

    def deploy_and_register_asset(self, contract_name, contract_file, constructor_parameters=None):
        assert self.default_registry

        token_address = self.deploy_contract(
            contract_name,
            contract_file,
            constructor_parameters,
        )
        self.default_registry.add_asset(token_address)  # pylint: disable=no-member

        return token_address


class Filter(object):
    def __init__(self, jsonrpc_client, filter_id_raw):
        self.filter_id_raw = filter_id_raw
        self.client = jsonrpc_client

    def changes(self):
        filter_changes = self.client.call(
            'eth_getFilterChanges',
            self.filter_id_raw,
        )

        # geth could return None
        if filter_changes is None:
            return []

        result = list()
        for log_event in filter_changes:
            address = address_decoder(log_event['address'])
            data = data_decoder(log_event['data'])
            topics = [
                decode_topic(topic)
                for topic in log_event['topics']
            ]

            result.append({
                'topics': topics,
                'data': data,
                'address': address,
            })

        return result

    def uninstall(self):
        self.client.call(
            'eth_uninstallFilter',
            self.filter_id_raw,
        )


class Discovery(object):
    """On chain smart contract raiden node discovery: allows registering
    endpoints (host, port) for your ethereum-/raiden-address and looking up
    endpoints for other ethereum-/raiden-addressess.
    """

    def __init__(
            self,
            jsonrpc_client,
            discovery_address,
            startgas=GAS_LIMIT,
            gasprice=GAS_PRICE,
            poll_timeout=DEFAULT_POLL_TIMEOUT):

        result = jsonrpc_client.call(
            'eth_getCode',
            address_encoder(discovery_address),
            'latest',
        )

        if result == '0x':
            raise ValueError('Discovery address {} does not contain code'.format(
                address_encoder(discovery_address),
            ))

        proxy = jsonrpc_client.new_abi_contract(
            ENDPOINT_REGISTRY_ABI,
            address_encoder(discovery_address),
        )

        self.address = discovery_address
        self.proxy = proxy
        self.client = jsonrpc_client
        self.startgas = startgas
        self.gasprice = gasprice
        self.poll_timeout = poll_timeout

    def register_endpoint(self, node_address, endpoint):
        if node_address != self.client.sender:
            raise ValueError("node_address doesnt match this node's address")

        transaction_hash = self.proxy.registerEndpoint.transact(endpoint)

        self.client.poll(
            transaction_hash.decode('hex'),
            timeout=self.poll_timeout,
        )

    def endpoint_by_address(self, node_address_bin):
        node_address_hex = node_address_bin.encode('hex')
        endpoint = self.proxy.findEndpointByAddress.call(node_address_hex)

        if endpoint is '':
            raise KeyError('Unknown address {}'.format(pex(node_address_bin)))

        return endpoint

    def address_by_endpoint(self, endpoint):
        address = self.proxy.findAddressByEndpoint.call(endpoint)

        if set(address) == {'0'}:  # the 0 address means nothing found
            return None

        return address.decode('hex')


class Asset(object):
    def __init__(
            self,
            jsonrpc_client,
            asset_address,
            startgas=GAS_LIMIT,
            gasprice=GAS_PRICE,
            poll_timeout=DEFAULT_POLL_TIMEOUT):
        # pylint: disable=too-many-arguments

        result = jsonrpc_client.call(
            'eth_getCode',
            address_encoder(asset_address),
            'latest',
        )

        if result == '0x':
            raise ValueError('Asset address {} does not contain code'.format(
                address_encoder(asset_address),
            ))

        proxy = jsonrpc_client.new_abi_contract(
            HUMAN_TOKEN_ABI,
            address_encoder(asset_address),
        )

        self.address = asset_address
        self.proxy = proxy
        self.client = jsonrpc_client
        self.startgas = startgas
        self.gasprice = gasprice
        self.poll_timeout = poll_timeout

    def approve(self, contract_address, allowance):
        """ Aprove `contract_address` to transfer up to `deposit` amount of token. """
        # TODO: check that `contract_address` is a netting channel and that
        # `self.address` is one of the participants (maybe add this logic into
        # `NettingChannel` and keep this straight forward)

        transaction_hash = self.proxy.approve.transact(
            contract_address,
            allowance,
            startgas=self.startgas,
            gasprice=self.gasprice,
        )
        self.client.poll(transaction_hash.decode('hex'), timeout=self.poll_timeout)

    def balance_of(self, address):
        """ Return the balance of `address`. """
        return self.proxy.balanceOf.call(address)

    def transfer(self, to_address, amount):
        transaction_hash = self.proxy.transfer.transact(  # pylint: disable=no-member
            to_address,
            amount,
            startgas=self.startgas,
            gasprice=self.gasprice,
        )
        self.client.poll(transaction_hash.decode('hex'))
        # TODO: check Transfer event


class Registry(object):
    def __init__(self, jsonrpc_client, registry_address, startgas=GAS_LIMIT,
                 gasprice=GAS_PRICE, poll_timeout=DEFAULT_POLL_TIMEOUT):
        # pylint: disable=too-many-arguments

        result = jsonrpc_client.call(
            'eth_getCode',
            address_encoder(registry_address),
            'latest',
        )

        if result == '0x':
            raise ValueError('Registry address {} does not contain code'.format(
                address_encoder(registry_address),
            ))

        proxy = jsonrpc_client.new_abi_contract(
            REGISTRY_ABI,
            address_encoder(registry_address),
        )

        self.address = registry_address
        self.proxy = proxy
        self.client = jsonrpc_client
        self.startgas = startgas
        self.gasprice = gasprice
        self.poll_timeout = poll_timeout

    def manager_address_by_asset(self, asset_address):
        """ Return the channel manager address for the given asset. """
        return self.proxy.channelManagerByAsset.call(asset_address)

    def add_asset(self, asset_address):
        transaction_hash = self.proxy.addAsset.transact(
            asset_address,
            startgas=self.startgas,
        )
        self.client.poll(transaction_hash.decode('hex'), timeout=self.poll_timeout)

        channel_manager_address_encoded = self.proxy.channelManagerByAsset.call(
            asset_address,
            startgas=self.startgas,
        )

        if not channel_manager_address_encoded:
            log.error('add_asset failed', asset_address=pex(asset_address))
            raise RuntimeError('add_asset failed')

        channel_manager_address_bin = address_decoder(channel_manager_address_encoded)

        log.info(
            'add_asset called',
            asset_address=pex(asset_address),
            registry_address=pex(self.address),
            channel_manager_address=pex(channel_manager_address_bin),
        )

    def asset_addresses(self):
        return [
            address_decoder(address)
            for address in self.proxy.assetAddresses.call(startgas=self.startgas)
        ]

    def manager_addresses(self):
        return [
            address_decoder(address)
            for address in self.proxy.channelManagerAddresses.call(startgas=self.startgas)
        ]

    def assetadded_filter(self):
        topics = [ASSETADDED_EVENTID]

        registry_address_bin = self.proxy.address
        filter_id_raw = new_filter(self.client, registry_address_bin, topics)

        return Filter(
            self.client,
            filter_id_raw,
        )


class ChannelManager(object):
    def __init__(
            self,
            jsonrpc_client,
            manager_address,
            startgas=GAS_LIMIT,
            gasprice=GAS_PRICE,
            poll_timeout=DEFAULT_POLL_TIMEOUT):
        # pylint: disable=too-many-arguments

        result = jsonrpc_client.call(
            'eth_getCode',
            address_encoder(manager_address),
            'latest',
        )

        if result == '0x':
            raise ValueError('Channel manager address {} does not contain code'.format(
                address_encoder(manager_address),
            ))

        proxy = jsonrpc_client.new_abi_contract(
            CHANNEL_MANAGER_ABI,
            address_encoder(manager_address),
        )

        self.address = manager_address
        self.proxy = proxy
        self.client = jsonrpc_client
        self.startgas = startgas
        self.gasprice = gasprice
        self.poll_timeout = poll_timeout

    def asset_address(self):
        """ Return the asset of this manager. """
        return address_decoder(self.proxy.tokenAddress.call())

    def new_netting_channel(self, peer1, peer2, settle_timeout):
        if not isaddress(peer1):
            raise ValueError('The pee1 must be a valid address')

        if not isaddress(peer2):
            raise ValueError('The peer2 must be a valid address')

        if privatekey_to_address(self.client.privkey) == peer1:
            other = peer2
        else:
            other = peer1

        transaction_hash = self.proxy.newChannel.transact(
            other,
            settle_timeout,
            startgas=self.startgas,
            gasprice=self.gasprice,
        )
        self.client.poll(transaction_hash.decode('hex'), timeout=self.poll_timeout)

        # TODO: raise if the transaction failed because there is an existing
        # channel in place

        netting_channel_address_encoded = self.proxy.getChannelWith.call(
            other,
            startgas=self.startgas,
        )

        if not netting_channel_address_encoded:
            log.error('netting_channel_address failed', peer1=pex(peer1), peer2=pex(peer2))
            raise RuntimeError('netting_channel_address failed')

        netting_channel_address_bin = address_decoder(netting_channel_address_encoded)

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
        channel_flat_encoded = self.proxy.getChannelsParticipants.call(startgas=self.startgas)

        channel_flat = [
            address_decoder(channel)
            for channel in channel_flat_encoded
        ]

        # [a,b,c,d] -> [(a,b),(c,d)]
        channel_iter = iter(channel_flat)
        return zip(channel_iter, channel_iter)

    def channels_by_participant(self, participant_address):  # pylint: disable=invalid-name
        """ Return a list of channel address that `participant_address` is a participant. """
        address_list = self.proxy.nettingContractsByAddress.call(
            participant_address,
            startgas=self.startgas,
        )

        return [
            address_decoder(address)
            for address in address_list
        ]

    def channelnew_filter(self):  # pylint: disable=unused-argument
        """ Install a new filter for ChannelNew events.

        Return:
            Filter: The filter instance.
        """
        # participant_address_hex = address_encoder(privatekey_to_address(self.client.privkey))
        # topics = [
        #     CHANNELNEW_EVENTID, [node_address_hex, None], [None, node_address_hex],
        # ]
        topics = [CHANNELNEW_EVENTID]

        channel_manager_address_bin = self.proxy.address
        filter_id_raw = new_filter(self.client, channel_manager_address_bin, topics)

        return Filter(
            self.client,
            filter_id_raw,
        )


class NettingChannel(object):
    def __init__(
            self,
            jsonrpc_client,
            channel_address,
            startgas=GAS_LIMIT,
            gasprice=GAS_PRICE,
            poll_timeout=DEFAULT_POLL_TIMEOUT):
        # pylint: disable=too-many-arguments

        result = jsonrpc_client.call(
            'eth_getCode',
            address_encoder(channel_address),
            'latest',
        )

        if result == '0x':
            raise ValueError('Netting channel address {} does not contain code'.format(
                address_encoder(channel_address),
            ))

        proxy = jsonrpc_client.new_abi_contract(
            NETTING_CHANNEL_ABI,
            address_encoder(channel_address),
        )

        self.address = channel_address
        self.proxy = proxy
        self.client = jsonrpc_client
        self.startgas = startgas
        self.gasprice = gasprice
        self.poll_timeout = poll_timeout

        # check we are a participant of the given channel
        self.node_address = privatekey_to_address(self.client.privkey)
        self.detail(self.node_address)

    def asset_address(self):
        return address_decoder(self.proxy.assetAddress.call())

    def detail(self, our_address):
        data = self.proxy.addressAndBalance.call(startgas=self.startgas)
        settle_timeout = self.proxy.settleTimeout.call(startgas=self.startgas)

        if data == '':
            raise RuntimeError('addressAndBalance call failed.')

        if settle_timeout == '':
            raise RuntimeError('settleTimeout call failed.')

        if address_decoder(data[0]) == our_address:
            return {
                'our_address': address_decoder(data[0]),
                'our_balance': data[1],
                'partner_address': address_decoder(data[2]),
                'partner_balance': data[3],
                'settle_timeout': settle_timeout,
            }

        if address_decoder(data[2]) == our_address:
            return {
                'our_address': address_decoder(data[2]),
                'our_balance': data[3],
                'partner_address': address_decoder(data[0]),
                'partner_balance': data[1],
                'settle_timeout': settle_timeout,
            }

        raise ValueError('We [{}] are not a participant of the given channel ({}, {})'.format(
            pex(our_address),
            data[0],
            data[2],
        ))

    def settle_timeout(self):
        settle_timeout = self.proxy.settleTimeout.call()
        return settle_timeout

    def isopen(self):
        if self.proxy.closed.call() != 0:
            return False

        return self.proxy.opened.call() != 0

    def partner(self, our_address):
        data = self.proxy.addressAndBalance.call()

        if address_decoder(data[0]) == our_address:
            return address_decoder(data[2])

        if address_decoder(data[2]) == our_address:
            return address_decoder(data[0])

        raise ValueError('We [{}] are not a participant of the given channel ({}, {})'.format(
            pex(our_address),
            data[0],
            data[2],
        ))

    def deposit(self, our_address, amount):  # pylint: disable=unused-argument
        if not isinstance(amount, (int, long)):
            raise ValueError('amount needs to be an integral number.')

        asset = Asset(
            self.client,
            self.asset_address(),
            poll_timeout=self.poll_timeout,
        )
        current_balance = asset.balance_of(self.node_address)

        if current_balance < amount:
            raise ValueError('deposit [{}] cant be larger than the available balance [{}].'.format(
                amount,
                current_balance,
            ))

        transaction_hash = self.proxy.deposit.transact(
            amount,
            startgas=self.startgas,
            gasprice=self.gasprice,
        )
        self.client.poll(transaction_hash.decode('hex'), timeout=self.poll_timeout)

        log.info('deposit called', contract=pex(self.address), amount=amount)

    def opened(self):
        return self.proxy.opened.call()

    def closed(self):
        return self.proxy.closed.call()

    def settled(self):
        return self.proxy.settled.call()

    def close(self, our_address, first_transfer, second_transfer):
        if first_transfer and second_transfer:
            first_encoded = first_transfer.encode()
            second_encoded = second_transfer.encode()

            transaction_hash = self.proxy.close.transact(
                first_encoded,
                second_encoded,
                startgas=self.startgas,
                gasprice=self.gasprice,
            )
            self.client.poll(transaction_hash.decode('hex'), timeout=self.poll_timeout)

            log.info(
                'close called',
                contract=pex(self.address),
                first_transfer=first_transfer,
                second_transfer=second_transfer,
            )

        elif first_transfer:
            first_encoded = first_transfer.encode()

            transaction_hash = self.proxy.closeSingleTransfer.transact(
                first_encoded,
                startgas=self.startgas,
                gasprice=self.gasprice,
            )
            self.client.poll(transaction_hash.decode('hex'), timeout=self.poll_timeout)

            log.info('close called', contract=pex(self.address), first_transfer=first_transfer)

        elif second_transfer:
            second_encoded = second_transfer.encode()

            transaction_hash = self.proxy.closeSingleTransfer.transact(
                second_encoded,
                startgas=self.startgas,
                gasprice=self.gasprice,
            )
            self.client.poll(transaction_hash.decode('hex'), timeout=self.poll_timeout)

            log.info('close called', contract=pex(self.address), second_transfer=second_transfer)

        else:
            # TODO: allow to close nevertheless
            raise ValueError('channel wasnt used')

    def update_transfer(self, our_address, their_transfer):
        if their_transfer is not None:
            their_transfer_encoded = their_transfer.encode()

            transaction_hash = self.proxy.updateTransfer.transact(
                their_transfer_encoded,
                startgas=self.startgas,
                gasprice=self.gasprice,
            )
            self.client.poll(transaction_hash.decode('hex'), timeout=self.poll_timeout)
            log.info(
                'update_transfer called',
                contract=pex(self.address),
                their_transfer=their_transfer,
            )
            # TODO: check if the ChannelSecretRevealed event was emitted and if
            # it wasn't raise an error

    def unlock(self, our_address, unlock_proofs):
        # force a list to get the length (could be a generator)
        unlock_proofs = list(unlock_proofs)
        log.info(
            '%s locks to unlock',
            len(unlock_proofs),
            contract=pex(self.address),
        )

        for merkle_proof, locked_encoded, secret in unlock_proofs:
            if isinstance(locked_encoded, messages.Lock):
                raise ValueError('unlock must be called with a lock encoded `.as_bytes`')

            merkleproof_encoded = ''.join(merkle_proof)

            transaction_hash = self.proxy.unlock.transact(
                locked_encoded,
                merkleproof_encoded,
                secret,
                startgas=self.startgas,
                gasprice=self.gasprice,
            )
            self.client.poll(transaction_hash.decode('hex'), timeout=self.poll_timeout)
            # TODO: check if the ChannelSecretRevealed event was emitted and if
            # it wasn't raise an error

            # if log.getEffectiveLevel() >= logging.INFO:  # only decode the lock if need to
            lock = messages.Lock.from_bytes(locked_encoded)
            log.info(
                'unlock called',
                contract=pex(self.address),
                lock=lock,
                secret=encode_hex(secret),
            )

    def settle(self):
        transaction_hash = self.proxy.settle.transact(
            startgas=self.startgas,
            gasprice=self.gasprice,
        )
        self.client.poll(transaction_hash.decode('hex'), timeout=self.poll_timeout)
        # TODO: check if the ChannelSettled event was emitted and if it wasn't raise an error
        log.info('settle called', contract=pex(self.address))

    def channelnewbalance_filter(self):
        """ Install a new filter for ChannelNewBalance events.

        Return:
            Filter: The filter instance.
        """
        netting_channel_address_bin = self.proxy.address
        topics = [CHANNELNEWBALANCE_EVENTID]

        filter_id_raw = new_filter(self.client, netting_channel_address_bin, topics)

        return Filter(
            self.client,
            filter_id_raw,
        )

    def channelsecretrevealed_filter(self):
        """ Install a new filter for ChannelSecret events.

        Return:
            Filter: The filter instance.
        """
        netting_channel_address_bin = self.proxy.address
        topics = [CHANNELSECRETREVEALED_EVENTID]

        filter_id_raw = new_filter(self.client, netting_channel_address_bin, topics)

        return Filter(
            self.client,
            filter_id_raw,
        )

    def channelclosed_filter(self):
        """ Install a new filter for ChannelClose events.

        Return:
            Filter: The filter instance.
        """
        topics = [CHANNELCLOSED_EVENTID]

        channel_manager_address_bin = self.proxy.address
        filter_id_raw = new_filter(self.client, channel_manager_address_bin, topics)

        return Filter(
            self.client,
            filter_id_raw,
        )

    def channelsettled_filter(self):
        """ Install a new filter for ChannelSettled events.

        Return:
            Filter: The filter instance.
        """
        topics = [CHANNELSETTLED_EVENTID]

        channel_manager_address_bin = self.proxy.address
        filter_id_raw = new_filter(self.client, channel_manager_address_bin, topics)

        return Filter(
            self.client,
            filter_id_raw,
        )
