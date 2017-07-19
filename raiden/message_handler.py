# -*- coding: utf-8 -*-
import logging

from ethereum import slogging

from raiden.encoding import messages
from raiden.exceptions import (
    UnknownAddress,
    TransferWhenClosed,
    TransferUnwanted,
    UnknownTokenAddress,
)
from raiden.token_swap import (
    SwapKey,
    TakerTokenSwapTask,
)
from raiden.transfer.events import (
    EventTransferReceivedSuccess,
)
from raiden.transfer.state import CHANNEL_STATE_OPENED
from raiden.transfer.mediated_transfer.state import (
    LockedTransferState,
)
from raiden.transfer.mediated_transfer.state_change import (
    ReceiveSecretRequest,
    ReceiveSecretReveal,
    ReceiveTransferRefund,
)
from raiden.transfer.state_change import ReceiveTransferDirect
from raiden.utils import pex, sha3

log = slogging.get_logger(__name__)  # pylint: disable=invalid-name


class RaidenMessageHandler(object):
    """ Class responsible to handle the protocol messages.

    Note:
        This class is not intended to be used standalone, use RaidenService
        instead.
    """
    def __init__(self, raiden):
        self.raiden = raiden
        self.blocked_tokens = []

    def on_message(self, message, msghash):  # noqa pylint: disable=unused-argument
        """ Handles `message` and sends an ACK on success. """
        if log.isEnabledFor(logging.INFO):
            log.info('message received', message=message)

        cmdid = message.cmdid

        # using explicity dispatch to make the code grepable
        if cmdid == messages.ACK:
            pass

        elif cmdid == messages.PING:
            pass

        elif cmdid == messages.SECRETREQUEST:
            self.message_secretrequest(message)

        elif cmdid == messages.REVEALSECRET:
            self.message_revealsecret(message)

        elif cmdid == messages.SECRET:
            self.message_secret(message)

        elif cmdid == messages.DIRECTTRANSFER:
            self.message_directtransfer(message)

        elif cmdid == messages.MEDIATEDTRANSFER:
            self.message_mediatedtransfer(message)

        elif cmdid == messages.REFUNDTRANSFER:
            self.message_refundtransfer(message)

        else:
            raise Exception("Unhandled message cmdid '{}'.".format(cmdid))

    def message_revealsecret(self, message):
        secret = message.secret
        sender = message.sender

        self.raiden.greenlet_task_dispatcher.dispatch_message(
            message,
            message.hashlock,
        )
        self.raiden.register_secret(secret)

        state_change = ReceiveSecretReveal(secret, sender)
        self.raiden.state_machine_event_handler.log_and_dispatch_to_all_tasks(state_change)

    def message_secretrequest(self, message):
        self.raiden.greenlet_task_dispatcher.dispatch_message(
            message,
            message.hashlock,
        )

        state_change = ReceiveSecretRequest(
            message.identifier,
            message.amount,
            message.hashlock,
            message.sender,
        )

        self.raiden.state_machine_event_handler.log_and_dispatch_by_identifier(
            message.identifier,
            state_change,
        )

    def message_secret(self, message):
        self.raiden.greenlet_task_dispatcher.dispatch_message(
            message,
            message.hashlock,
        )

        try:
            # register the secret with all channels interested in it (this
            # must not withdraw or unlock otherwise the state changes could
            # flow in the wrong order in the path)
            self.raiden.register_secret(message.secret)

            secret = message.secret
            identifier = message.identifier
            token = message.token
            secret = message.secret
            hashlock = sha3(secret)

            self.raiden.handle_secret(
                identifier,
                token,
                secret,
                message,
                hashlock,
            )
        except:  # pylint: disable=bare-except
            log.exception('Unhandled exception')

        state_change = ReceiveSecretReveal(
            message.secret,
            message.sender,
        )

        self.raiden.state_machine_event_handler.log_and_dispatch_by_identifier(
            message.identifier,
            state_change,
        )

    def message_refundtransfer(self, message):
        self.raiden.greenlet_task_dispatcher.dispatch_message(
            message,
            message.lock.hashlock,
        )

        transfer_state = LockedTransferState(
            identifier=message.identifier,
            amount=message.lock.amount,
            token=message.token,
            initiator=message.initiator,
            target=message.target,
            expiration=message.lock.expiration,
            hashlock=message.lock.hashlock,
            secret=None,
        )
        state_change = ReceiveTransferRefund(
            message.sender,
            transfer_state,
        )
        self.raiden.state_machine_event_handler.log_and_dispatch_by_identifier(
            message.identifier,
            state_change,
        )

    def message_directtransfer(self, message):
        if message.token not in self.raiden.token_to_channelgraph:
            raise UnknownTokenAddress('Unknown token address {}'.format(pex(message.token)))

        if message.token in self.blocked_tokens:
            raise TransferUnwanted()

        graph = self.raiden.token_to_channelgraph[message.token]

        if not graph.has_channel(self.raiden.address, message.sender):
            raise UnknownAddress(
                'Direct transfer from node without an existing channel: {}'.format(
                    pex(message.sender),
                )
            )

        channel = graph.partneraddress_to_channel[message.sender]

        if channel.state != CHANNEL_STATE_OPENED:
            raise TransferWhenClosed(
                'Direct transfer received for a closed channel: {}'.format(
                    pex(channel.channel_address),
                )
            )

        amount = message.transferred_amount - channel.partner_state.transferred_amount
        state_change = ReceiveTransferDirect(
            message.identifier,
            amount,
            message.token,
            message.sender,
        )
        state_change_id = self.raiden.transaction_log.log(state_change)

        channel.register_transfer(
            self.raiden.get_block_number(),
            message,
        )

        receive_success = EventTransferReceivedSuccess(
            message.identifier,
        )
        self.raiden.transaction_log.log_events(
            state_change_id,
            [receive_success],
            self.raiden.get_block_number()
        )

    def message_mediatedtransfer(self, message):
        # TODO: Reject mediated transfer that the hashlock/identifier is known,
        # this is a downstream bug and the transfer is going in cycles (issue #490)

        key = SwapKey(
            message.identifier,
            message.token,
            message.lock.amount,
        )

        if message.token in self.blocked_tokens:
            raise TransferUnwanted()

        # TODO: add a separate message for token swaps to simplify message
        # handling (issue #487)
        if key in self.raiden.swapkeys_tokenswaps:
            self.message_tokenswap(message)
            return

        graph = self.raiden.token_to_channelgraph[message.token]

        if not graph.has_channel(self.raiden.address, message.sender):
            raise UnknownAddress(
                'Mediated transfer from node without an existing channel: {}'.format(
                    pex(message.sender),
                )
            )

        channel = graph.partneraddress_to_channel[message.sender]

        if channel.state != CHANNEL_STATE_OPENED:
            raise TransferWhenClosed(
                'Mediated transfer received but the channel is closed: {}'.format(
                    pex(channel.channel_address),
                )
            )

        # raises if the message is invalid
        channel.register_transfer(
            self.raiden.get_block_number(),
            message
        )

        if message.target == self.raiden.address:
            self.raiden.target_mediated_transfer(message)
        else:
            self.raiden.mediate_mediated_transfer(message)

    def message_tokenswap(self, message):
        key = SwapKey(
            message.identifier,
            message.token,
            message.lock.amount,
        )

        # If we are the maker the task is already running and waiting for the
        # taker's MediatedTransfer
        task = self.raiden.swapkeys_greenlettasks.get(key)
        if task:
            task.response_queue.put(message)

        # If we are the taker we are receiving the maker transfer and should
        # start our new task
        else:
            token_swap = self.raiden.swapkeys_tokenswaps[key]
            task = TakerTokenSwapTask(
                self.raiden,
                token_swap,
                message,
            )
            task.start()

            self.raiden.swapkeys_greenlettasks[key] = task
