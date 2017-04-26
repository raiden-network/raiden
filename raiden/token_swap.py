# -*- coding: utf-8 -*-
import logging
import random
import time
from collections import namedtuple, defaultdict

import gevent
from gevent.queue import Empty
from ethereum import slogging
from ethereum.utils import sha3

from raiden.tasks import Task
from raiden.messages import (
    MediatedTransfer,
    RefundTransfer,
    RevealSecret,
    Secret,
    SecretRequest,
)
from raiden.settings import (
    DEFAULT_EVENTS_POLL_TIMEOUT,
)
from raiden.utils import lpex, pex

log = slogging.get_logger(__name__)  # pylint: disable=invalid-name
TIMEOUT = object()

TokenSwap = namedtuple('TokenSwap', (
    'identifier',
    'from_token',
    'from_amount',
    'from_nodeaddress',  # the node address of the owner of the `from_token`
    'to_token',
    'to_amount',
    'to_nodeaddress',  # the node address of the owner of the `to_token`
))
SwapKey = namedtuple('SwapKey', (
    'identifier',
    'from_token',
    'from_amount',
))


class GreenletTasksDispatcher(object):
    def __init__(self):
        self.hashlocks_greenlets = defaultdict(list)

    def register_task(self, task, hashlock):
        """ Register the task to receive messages based on `hashlock`.

        Registration is required otherwise the task won't receive any messages
        from the protocol, un-registering is done by the `unregister_task`
        function.

        Note:
            Messages are dispatched solely on the hashlock value (being part of
            the message, eg. SecretRequest, or calculated from the message
            content, eg.  RevealSecret), this means the sender needs to be
            checked for the received messages.
        """
        if not isinstance(task, Task):
            raise ValueError('task must be an instance of Task')

        self.hashlocks_greenlets[hashlock].append(task)

    def unregister_task(self, task, hashlock, success):  # pylint: disable=unused-argument
        """ Clear the task when it's finished. """
        self.hashlocks_greenlets[hashlock].remove(task)

        if len(self.hashlocks_greenlets[hashlock]) == 0:
            del self.hashlocks_greenlets[hashlock]

    def dispatch_message(self, message, hashlock):
        for task in self.hashlocks_greenlets[hashlock]:
            task.response_queue.put(message)

    def stop(self):
        wait_for = list()

        for greenlets in self.hashlocks_greenlets.itervalues():
            for task in greenlets:
                task.kill()

            wait_for.extend(greenlets)

        return wait_for


class BaseMediatedTransferTask(Task):
    def _send_and_wait_time(self, raiden, recipient, transfer, timeout):
        """ Utility to handle multiple messages for the same hashlock while
        properly handling expiration timeouts.
        """

        current_time = time.time()
        limit_time = current_time + timeout

        raiden.send_async(recipient, transfer)

        while current_time <= limit_time:
            # wait for a response message (not the Ack for the transfer)
            try:
                response = self.response_queue.get(
                    timeout=limit_time - current_time,
                )
            except Empty:
                yield TIMEOUT
                return

            yield response

            current_time = time.time()

        if log.isEnabledFor(logging.DEBUG):
            log.debug(
                'TIMED OUT %s %s',
                self.__class__,
                pex(transfer),
            )

    def _send_and_wait_block(self, raiden, recipient, transfer, expiration_block):
        """ Utility to handle multiple messages and timeout on a blocknumber. """
        raiden.send_async(recipient, transfer)

        current_block = raiden.get_block_number()
        while current_block < expiration_block:
            try:
                response = self.response_queue.get(
                    timeout=DEFAULT_EVENTS_POLL_TIMEOUT,
                )
            except Empty:
                pass
            else:
                if response:
                    yield response

            current_block = raiden.get_block_number()

        if log.isEnabledFor(logging.DEBUG):
            log.debug(
                'TIMED OUT ON BLOCK %s %s %s',
                current_block,
                self.__class__,
                pex(transfer),
            )

        yield TIMEOUT

    def _messages_until_block(self, raiden, expiration_block):
        """ Returns the received messages up to the block `expiration_block`.
        """
        current_block = raiden.get_block_number()
        while current_block < expiration_block:
            try:
                response = self.response_queue.get(
                    timeout=DEFAULT_EVENTS_POLL_TIMEOUT,
                )
            except Empty:
                pass
            else:
                if response:
                    yield response

            current_block = raiden.get_block_number()

    def _wait_for_unlock_or_close(self, raiden, graph, channel, mediated_transfer):  # noqa
        """ Wait for a Secret message from our partner to update the local
        state, if the Secret message is not sent within time the channel will
        be closed.

        Note:
            Must be called only once the secret is known.
            Must call `unregister_task` after this function returns.
        """
        assert graph.token_address == mediated_transfer.token

        if not isinstance(mediated_transfer, MediatedTransfer):
            raise ValueError('MediatedTransfer expected.')

        block_to_close = mediated_transfer.lock.expiration - raiden.config['reveal_timeout']
        hashlock = mediated_transfer.lock.hashlock
        identifier = mediated_transfer.identifier
        token = mediated_transfer.token

        while channel.our_state.balance_proof.is_unclaimed(hashlock):
            current_block = raiden.get_block_number()

            if current_block > block_to_close:
                if log.isEnabledFor(logging.WARN):
                    log.warn(
                        'Closing channel (%s, %s) to prevent expiration of lock %s %s',
                        pex(channel.our_state.address),
                        pex(channel.partner_state.address),
                        pex(hashlock),
                        repr(self),
                    )

                channel.external_state.close(
                    channel.our_state.address,
                    channel.partner_state.balance_proof.transfer,
                )
                return

            try:
                response = self.response_queue.get(
                    timeout=DEFAULT_EVENTS_POLL_TIMEOUT
                )
            except Empty:
                pass
            else:
                if isinstance(response, Secret):
                    secret = response.secret
                    hashlock = sha3(secret)

                    if response.identifier == identifier and response.token == token:
                        raiden.handle_secret(
                            identifier,
                            graph.token_address,
                            secret,
                            response,
                            hashlock,
                        )
                    else:
                        # cannot use the message but the secret is okay
                        raiden.handle_secret(
                            identifier,
                            graph.token_address,
                            secret,
                            None,
                            hashlock,
                        )

                        if log.isEnabledFor(logging.ERROR):
                            log.error(
                                'Invalid Secret message received, expected message'
                                ' for token=%s identifier=%s received=%s',
                                token,
                                identifier,
                                response,
                            )

                elif isinstance(response, RevealSecret):
                    secret = response.secret
                    hashlock = sha3(secret)
                    raiden.handle_secret(
                        identifier,
                        graph.token_address,
                        secret,
                        None,
                        hashlock,
                    )

                elif log.isEnabledFor(logging.ERROR):
                    log.error(
                        'Invalid message ignoring. %s %s',
                        repr(response),
                        repr(self),
                    )

    def _wait_expiration(self, raiden, transfer, sleep=DEFAULT_EVENTS_POLL_TIMEOUT):
        """ Utility to wait until the expiration block.

        For a chain A-B-C, if an attacker controls A and C a mediated transfer
        can be done through B and C will wait for/send a timeout, for that
        reason B must not unregister the hashlock until the lock has expired,
        otherwise the revealed secret wouldn't be caught.
        """
        # pylint: disable=no-self-use

        expiration = transfer.lock.expiration + 1

        while True:
            current_block = raiden.get_block_number()

            if current_block > expiration:
                return

            gevent.sleep(sleep)


# Note: send_and_wait_valid methods are used to check the message type and
# sender only, this can be improved by using a encrypted connection between the
# nodes making the signature validation unnecessary


# TODO: Implement the swaps as a restartable task (issue #303)
class MakerTokenSwapTask(BaseMediatedTransferTask):
    """ Initiator task, responsible to choose a random secret, initiate the
    token swap by sending a mediated transfer to the counterparty and
    revealing the secret once the swap is complete.
    """

    def __init__(self, raiden, tokenswap, async_result):
        super(MakerTokenSwapTask, self).__init__()

        self.raiden = raiden
        self.tokenswap = tokenswap
        self.async_result = async_result

    def __repr__(self):
        tokenswap = self.tokenswap
        return '<{} {} from_token:{} to_token:{}>'.format(
            self.__class__.__name__,
            pex(self.raiden.address),
            pex(tokenswap.from_token),
            pex(tokenswap.to_token),
        )

    def _run(self):  # pylint: disable=method-hidden,too-many-locals
        tokenswap = self.tokenswap
        raiden = self.raiden

        identifier = tokenswap.identifier
        from_token = tokenswap.from_token
        from_amount = tokenswap.from_amount
        to_token = tokenswap.to_token
        to_amount = tokenswap.to_amount
        to_nodeaddress = tokenswap.to_nodeaddress

        from_graph = raiden.channelgraphs[from_token]
        to_graph = raiden.channelgraphs[to_token]

        from_routes = from_graph.get_best_routes(
            raiden.address,
            to_nodeaddress,
            from_amount,
            lock_timeout=None,
        )
        fee = 0

        for path, from_channel in from_routes:
            # for each new path a new secret must be used
            secret = sha3(hex(random.getrandbits(256)))
            hashlock = sha3(secret)

            raiden.greenlet_task_dispatcher.register_task(self, hashlock)
            raiden.register_channel_for_hashlock(from_token, from_channel, hashlock)

            lock_expiration = (
                raiden.get_block_number() +
                from_channel.settle_timeout -
                raiden.config['reveal_timeout']
            )

            from_mediated_transfer = from_channel.create_mediatedtransfer(
                raiden.address,
                to_nodeaddress,
                fee,
                from_amount,
                identifier,
                lock_expiration,
                hashlock,
            )
            raiden.sign(from_mediated_transfer)
            from_channel.register_transfer(from_mediated_transfer)

            # wait for the SecretRequest and MediatedTransfer
            to_mediated_transfer = self.send_and_wait_valid_state(
                raiden,
                path,
                from_mediated_transfer,
                to_token,
                to_amount,
            )

            if to_mediated_transfer is None:
                # the initiator can unregister right away since it knows the
                # secret wont be revealed
                raiden.greenlet_task_dispatcher.unregister_task(self, hashlock, False)

            elif isinstance(to_mediated_transfer, MediatedTransfer):
                to_hop = to_mediated_transfer.sender
                to_channel = to_graph.partneraddress_channel[to_hop]

                to_channel.register_transfer(to_mediated_transfer)
                raiden.register_channel_for_hashlock(to_token, to_channel, hashlock)

                # A swap is composed of two mediated transfers, we need to
                # reveal the secret to both, since the maker is one of the ends
                # we just need to send the reveal secret directly to the taker.
                reveal_secret = RevealSecret(secret)
                raiden.sign(reveal_secret)
                raiden.send_async(to_nodeaddress, reveal_secret)

                from_channel.register_secret(secret)

                # Register the secret with the to_channel and send the
                # RevealSecret message to the node that is paying the to_token
                # (this node might, or might not be the same as the taker),
                # then wait for the withdraw.
                raiden.handle_secret(
                    identifier,
                    to_token,
                    secret,
                    None,
                    hashlock,
                )

                to_channel = to_graph.partneraddress_channel[to_mediated_transfer.sender]
                self._wait_for_unlock_or_close(
                    raiden,
                    to_graph,
                    to_channel,
                    to_mediated_transfer,
                )

                # unlock the from_token and optimistically reveal the secret
                # forward
                raiden.handle_secret(
                    identifier,
                    from_token,
                    secret,
                    None,
                    hashlock,
                )

                raiden.greenlet_task_dispatcher.unregister_task(self, hashlock, True)
                self.async_result.set(True)
                return

        if log.isEnabledFor(logging.DEBUG):
            node_address = raiden.address
            log.debug(
                'MAKER TOKEN SWAP FAILED initiator:%s to_nodeaddress:%s',
                pex(node_address),
                pex(to_nodeaddress),
            )

        # all routes failed
        self.async_result.set(False)

    def send_and_wait_valid_state(  # noqa
            self,
            raiden,
            path,
            from_token_transfer,
            to_token,
            to_amount):
        """ Start the swap by sending the first mediated transfer to the
        taker and wait for mediated transfer for the exchanged token.

        This method will validate the messages received, discard the invalid
        ones, and wait until a valid state is reached. The valid state is
        reached when a mediated transfer for `to_token` with `to_amount` tokens
        and a SecretRequest from the taker are received.

        Returns:
            None: when the timeout was reached.
            MediatedTransfer: when a valid state is reached.
            RefundTransfer: when an invalid state is reached by
                our partner.
        """
        # pylint: disable=too-many-arguments

        next_hop = path[1]
        taker_address = path[-1]  # taker_address and next_hop might be equal

        # a valid state must have a secret request from the maker and a valid
        # mediated transfer for the new token
        received_secretrequest = False
        mediated_transfer = None

        response_iterator = self._send_and_wait_time(
            raiden,
            from_token_transfer.recipient,
            from_token_transfer,
            raiden.config['msg_timeout'],
        )

        for response in response_iterator:
            transfer_is_valid_mediated_transfer = (
                isinstance(response, MediatedTransfer) and
                response.token == to_token and

                # we need a lower expiration because:
                # - otherwise the previous node is not operating correctly
                # - we assume that received mediated transfer has a smaller
                #   expiration to properly call close on edge cases
                response.lock.expiration <= from_token_transfer.lock.expiration
            )

            if response is None:
                if log.isEnabledFor(logging.DEBUG):
                    log.debug(
                        'MAKER SWAP TIMED OUT hashlock:%s',
                        pex(from_token_transfer.lock.hashlock),
                    )

                return None

            # The MediatedTransfer might be from `next_hop` or most likely from
            # a different node.
            if transfer_is_valid_mediated_transfer:
                if response.lock.amount == to_amount:
                    mediated_transfer = response

            elif isinstance(response, SecretRequest) and response.sender == taker_address:
                received_secretrequest = True

            elif isinstance(response, RefundTransfer) and response.sender == next_hop:
                return response

            # The other participant must not use a direct transfer to finish
            # the token swap, ignore it
            elif log.isEnabledFor(logging.ERROR):
                log.error(
                    'Invalid message ignoring. %s',
                    repr(response),
                )

            if mediated_transfer and received_secretrequest:
                return mediated_transfer

        return None


class TakerTokenSwapTask(BaseMediatedTransferTask):
    """ Taker task, responsible to receive a MediatedTransfer for the
    from_transfer and forward a to_transfer with the same hashlock.
    """

    def __init__(
            self,
            raiden,
            tokenswap,
            from_mediated_transfer):

        super(TakerTokenSwapTask, self).__init__()

        self.raiden = raiden
        self.from_mediated_transfer = from_mediated_transfer
        self.tokenswap = tokenswap

    def __repr__(self):
        return '<{} {} from_token:{} to_token:{}>'.format(
            self.__class__.__name__,
            pex(self.raiden.address),
            pex(self.from_mediated_transfer.token),
            pex(self.tokenswap.to_token),
        )

    def _run(self):  # pylint: disable=method-hidden,too-many-locals
        fee = 0
        raiden = self.raiden
        tokenswap = self.tokenswap

        # this is the MediatedTransfer that wil pay the maker's half of the
        # swap, not necessarily from him
        maker_paying_transfer = self.from_mediated_transfer

        # this is the address of the node that the taker actually has a channel
        # with (might or might not be the maker)
        maker_payer_hop = maker_paying_transfer.sender

        assert tokenswap.identifier == maker_paying_transfer.identifier
        assert tokenswap.from_token == maker_paying_transfer.token
        assert tokenswap.from_amount == maker_paying_transfer.lock.amount
        assert tokenswap.from_nodeaddress == maker_paying_transfer.initiator

        maker_receiving_token = tokenswap.to_token
        to_amount = tokenswap.to_amount

        identifier = maker_paying_transfer.identifier
        hashlock = maker_paying_transfer.lock.hashlock
        maker_address = maker_paying_transfer.initiator

        taker_receiving_token = maker_paying_transfer.token
        taker_paying_token = maker_receiving_token

        from_graph = raiden.channelgraphs[taker_receiving_token]
        from_channel = from_graph.partneraddress_channel[maker_payer_hop]

        to_graph = raiden.channelgraphs[maker_receiving_token]

        # update the channel's distributable and merkle tree
        from_channel.register_transfer(maker_paying_transfer)

        # register the task to receive Refund/Secrect/RevealSecret messages
        raiden.greenlet_task_dispatcher.register_task(self, hashlock)
        raiden.register_channel_for_hashlock(taker_receiving_token, from_channel, hashlock)

        # send to the maker a secret request informing how much the taker will
        # be _paid_, this is used to inform the maker that his part of the
        # mediated transfer is okay
        secret_request = SecretRequest(
            identifier,
            maker_paying_transfer.lock.hashlock,
            maker_paying_transfer.lock.amount,
        )
        raiden.sign(secret_request)
        raiden.send_async(maker_address, secret_request)

        lock_expiration = maker_paying_transfer.lock.expiration - raiden.config['reveal_timeout']
        lock_timeout = lock_expiration - raiden.get_block_number()

        # Note: taker may only try different routes if a RefundTransfer is
        # received, because the maker is the node controlling the secret
        available_routes = to_graph.get_best_routes(
            raiden.address,
            maker_address,
            maker_paying_transfer.lock.amount,
            lock_timeout,
        )

        if not available_routes:
            if log.isEnabledFor(logging.DEBUG):
                node_address = raiden.address
                log.debug(
                    'TAKER TOKEN SWAP FAILED, NO ROUTES initiator:%s from_nodeaddress:%s',
                    pex(node_address),
                    pex(maker_address),
                )

            return

        first_transfer = None
        for to_path, taker_paying_channel in available_routes:
            taker_paying_hop = to_path[1]

            if log.isEnabledFor(logging.DEBUG):
                log.debug(
                    'TAKER TOKEN SWAP %s -> %s msghash:%s hashlock:%s',
                    pex(maker_paying_transfer.target),
                    pex(maker_address),
                    pex(maker_paying_transfer.hash),
                    pex(hashlock),
                )

            # make a paying MediatedTransfer with same hashlock/identifier and the
            # taker's paying token/amount
            taker_paying_transfer = taker_paying_channel.create_mediatedtransfer(
                raiden.address,
                maker_address,
                fee,
                to_amount,
                identifier,
                lock_expiration,
                hashlock,
            )
            raiden.sign(taker_paying_transfer)
            taker_paying_channel.register_transfer(taker_paying_transfer)

            if not first_transfer:
                first_transfer = taker_paying_transfer

            if log.isEnabledFor(logging.DEBUG):
                log.debug(
                    'EXCHANGE TRANSFER NEW PATH path:%s hashlock:%s',
                    lpex(taker_paying_hop),
                    pex(hashlock),
                )

            # register the task to receive Refund/Secrect/RevealSecret messages
            raiden.register_channel_for_hashlock(
                maker_receiving_token,
                taker_paying_channel,
                hashlock,
            )

            response, secret = self.send_and_wait_valid(
                raiden,
                taker_paying_transfer,
                maker_payer_hop,
            )

            # only refunds for `maker_receiving_token` must be considered
            # (check send_and_wait_valid)
            if isinstance(response, RefundTransfer):
                if response.lock.amount != taker_paying_transfer.amount:
                    log.info(
                        'Partner %s sent an invalid refund message with an invalid amount',
                        pex(taker_paying_hop),
                    )
                    raiden.greenlet_task_dispatcher.unregister_task(self, hashlock, False)
                    return
                else:
                    taker_paying_channel.register_transfer(response)

            elif isinstance(response, RevealSecret):
                # the secret was registered by the message handler

                # wait for the taker_paying_hop to reveal the secret prior to
                # unlocking locally
                if response.sender != taker_paying_hop:
                    response = self.wait_reveal_secret(
                        raiden,
                        taker_paying_hop,
                        taker_paying_transfer.lock.expiration,
                    )

                # unlock and send the Secret message
                raiden.handle_secret(
                    identifier,
                    taker_paying_token,
                    response.secret,
                    None,
                    hashlock,
                )

                # if the secret arrived early, withdraw it, otherwise send the
                # RevealSecret forward in the maker-path
                if secret:
                    raiden.handle_secret(
                        identifier,
                        taker_receiving_token,
                        response.secret,
                        secret,
                        hashlock,
                    )

                # wait for the withdraw in case it did not happen yet
                self._wait_for_unlock_or_close(
                    raiden,
                    from_graph,
                    from_channel,
                    maker_paying_transfer,
                )

                return

            # the lock expired
            else:
                if log.isEnabledFor(logging.DEBUG):
                    node_address = raiden.address
                    log.debug(
                        'TAKER TOKEN SWAP FAILED initiator:%s from_nodeaddress:%s',
                        pex(node_address),
                        pex(maker_address),
                    )

                self.async_result.set(False)
                return

        # no route is available, wait for the sent mediated transfer to expire
        self._wait_expiration(raiden, first_transfer)

        if log.isEnabledFor(logging.DEBUG):
            node_address = raiden.address
            log.debug(
                'TAKER TOKEN SWAP FAILED initiator:%s from_nodeaddress:%s',
                pex(node_address),
                pex(maker_address),
            )

        self.async_result.set(False)

    def send_and_wait_valid(self, raiden, mediated_transfer, maker_payer_hop):
        """ Start the second half of the exchange and wait for the SecretReveal
        for it.

        This will send the taker mediated transfer with the maker as a target,
        once the maker receives the transfer he is expected to send a
        RevealSecret backwards.
        """

        # the taker cannot discard the transfer since the secret is controlled
        # by another node (the maker), so we have no option but to wait for a
        # valid response until the lock expires
        response_iterator = self._send_and_wait_block(
            raiden,
            mediated_transfer.recipient,
            mediated_transfer,
            mediated_transfer.lock.expiration,
        )

        # Usually the RevealSecret for the MediatedTransfer from this node to
        # the maker should arrive first, but depending on the number of hops
        # and if the maker-path is optimistically revealing the Secret, then
        # the Secret message might arrive first.
        secret = None

        for response in response_iterator:
            valid_reveal = (
                isinstance(response, RevealSecret) and
                response.hashlock == mediated_transfer.lock.hashlock and
                response.sender == maker_payer_hop
            )

            valid_refund = (
                isinstance(response, RefundTransfer) and
                response.sender == maker_payer_hop and
                response.lock.amount == mediated_transfer.lock.amount and
                response.lock.expiration <= mediated_transfer.lock.expiration and
                response.token == mediated_transfer.token
            )

            if response is None:
                log.error(
                    'TAKER SWAP TIMED OUT node:%s hashlock:%s',
                    pex(raiden.address),
                    pex(mediated_transfer.lock.hashlock),
                )
                return (response, secret)

            elif isinstance(response, Secret):
                if sha3(response.secret) != mediated_transfer.lock.hashlock:
                    log.error("Secret doesn't match the hashlock, ignoring.")
                    continue

                secret = response

            elif valid_reveal:
                return (response, secret)

            elif valid_refund:
                return (response, secret)

            elif log.isEnabledFor(logging.ERROR):
                log.error(
                    'Invalid message [%s] supplied to the task, ignoring.',
                    repr(response),
                )

        return (None, secret)

    def wait_reveal_secret(self, raiden, taker_paying_hop, expiration_block):
        for response in self._messages_until_block(raiden, expiration_block):
            if isinstance(response, RevealSecret) and response.sender == taker_paying_hop:
                return response

            elif log.isEnabledFor(logging.ERROR):
                log.error(
                    'Invalid message [%s] supplied to the task, ignoring.',
                    repr(response),
                )
