# -*- coding: utf-8 -*-
import itertools
import logging

import gevent
from ethereum import slogging

from raiden.messages import (
    RevealSecret,
    SecretRequest,
)
from raiden.transfer.mediated_transfer.state_change import (
    ContractReceiveBalance,
    ContractReceiveClosed,
    ContractReceiveNewChannel,
    ContractReceiveSettled,
    ContractReceiveTokenAdded,
    ContractReceiveWithdraw,
)
from raiden.transfer.events import (
    EventTransferSentSuccess,
    EventTransferSentFailed,
    EventTransferReceivedSuccess,
)
from raiden.transfer.mediated_transfer.events import (
    ContractSendChannelClose,
    ContractSendWithdraw,
    EventUnlockFailed,
    EventUnlockSuccess,
    EventWithdrawFailed,
    EventWithdrawSuccess,
    SendBalanceProof,
    SendMediatedTransfer,
    SendRefundTransfer,
    SendRevealSecret,
    SendSecretRequest,
)
from raiden.utils import sha3, pex

log = slogging.get_logger(__name__)  # pylint: disable=invalid-name
UNEVENTFUL_EVENTS = (
    EventTransferReceivedSuccess,
    EventUnlockSuccess,
    EventWithdrawFailed,
    EventWithdrawSuccess,

    # The withdraw is currently handled by the netting channel, once the close
    # event is detected all locks will be withdrawn
    ContractSendWithdraw,
)


class StateMachineEventHandler:
    def __init__(self, raiden):
        self.raiden = raiden

    def log_and_dispatch_to_all_tasks(self, state_change):
        """Log a state change, dispatch it to all state managers and log generated events"""
        state_change_id = self.raiden.transaction_log.log(state_change)
        manager_lists = self.raiden.identifier_to_statemanagers.values()

        for manager in itertools.chain(*manager_lists):
            events = self.dispatch(manager, state_change)
            self.raiden.transaction_log.log_events(
                state_change_id,
                events,
                self.raiden.get_block_number()
            )

    def log_and_dispatch_by_identifier(self, identifier, state_change):
        """Log a state change, dispatch it to the state manager corresponding to `idenfitier`
        and log generated events"""
        state_change_id = self.raiden.transaction_log.log(state_change)
        manager_list = self.raiden.identifier_to_statemanagers[identifier]

        for manager in manager_list:
            events = self.dispatch(manager, state_change)
            self.raiden.transaction_log.log_events(
                state_change_id,
                events,
                self.raiden.get_block_number()
            )

    def log_and_dispatch(self, state_manager, state_change):
        """Log a state change, dispatch it to the given state manager and log generated events"""
        state_change_id = self.raiden.transaction_log.log(state_change)
        events = self.dispatch(state_manager, state_change)
        self.raiden.transaction_log.log_events(
            state_change_id,
            events,
            self.raiden.get_block_number()
        )

    def dispatch(self, state_manager, state_change):
        all_events = state_manager.dispatch(state_change)

        for event in all_events:
            self.on_event(event)

        return all_events

    def on_event(self, event):
        if isinstance(event, SendMediatedTransfer):
            receiver = event.receiver
            fee = 0
            graph = self.raiden.token_to_channelgraph[event.token]
            channel = graph.partneraddress_to_channel[receiver]

            mediated_transfer = channel.create_mediatedtransfer(
                event.initiator,
                event.target,
                fee,
                event.amount,
                event.identifier,
                event.expiration,
                event.hashlock,
            )

            self.raiden.sign(mediated_transfer)
            channel.register_transfer(
                self.raiden.get_block_number(),
                mediated_transfer,
            )
            self.raiden.send_async(receiver, mediated_transfer)

        elif isinstance(event, SendRevealSecret):
            reveal_message = RevealSecret(event.secret)
            self.raiden.sign(reveal_message)
            self.raiden.send_async(event.receiver, reveal_message)

        elif isinstance(event, SendBalanceProof):
            # unlock and update remotely (send the Secret message)
            self.raiden.handle_secret(
                event.identifier,
                event.token,
                event.secret,
                None,
                sha3(event.secret),
            )

        elif isinstance(event, SendSecretRequest):
            secret_request = SecretRequest(
                event.identifier,
                event.hashlock,
                event.amount,
            )
            self.raiden.sign(secret_request)
            self.raiden.send_async(event.receiver, secret_request)

        elif isinstance(event, SendRefundTransfer):
            receiver = event.receiver
            fee = 0
            graph = self.raiden.token_to_channelgraph[event.token]
            channel = graph.partneraddress_to_channel[receiver]

            refund_transfer = channel.create_refundtransfer(
                event.initiator,
                event.target,
                fee,
                event.amount,
                event.identifier,
                event.expiration,
                event.hashlock,
            )

            self.raiden.sign(refund_transfer)
            channel.register_transfer(
                self.raiden.get_block_number(),
                refund_transfer,
            )
            self.raiden.send_async(receiver, refund_transfer)

        elif isinstance(event, EventTransferSentSuccess):
            for result in self.raiden.identifier_to_results[event.identifier]:
                result.set(True)

        elif isinstance(event, EventTransferSentFailed):
            for result in self.raiden.identifier_to_results[event.identifier]:
                result.set(False)
        elif isinstance(event, UNEVENTFUL_EVENTS):
            pass
        elif isinstance(event, EventUnlockFailed):
            log.error(
                'UnlockFailed!',
                hashlock=pex(event.hashlock),
                reason=event.reason
            )

        elif isinstance(event, ContractSendChannelClose):
            graph = self.raiden.token_to_channelgraph[event.token]
            channel = graph.address_to_channel[event.channel_address]

            balance_proof = channel.our_state.balance_proof
            channel.external_state.close(balance_proof)

        else:
            log.error('Unknown event {}'.format(type(event)))

    def on_blockchain_statechange(self, state_change):
        if log.isEnabledFor(logging.INFO):
            log.info('state_change received', state_change=state_change)
        self.raiden.transaction_log.log(state_change)

        if isinstance(state_change, ContractReceiveTokenAdded):
            self.handle_tokenadded(state_change)

        elif isinstance(state_change, ContractReceiveNewChannel):
            self.handle_channelnew(state_change)

        elif isinstance(state_change, ContractReceiveBalance):
            self.handle_balance(state_change)

        elif isinstance(state_change, ContractReceiveClosed):
            self.handle_closed(state_change)

        elif isinstance(state_change, ContractReceiveSettled):
            self.handle_settled(state_change)

        elif isinstance(state_change, ContractReceiveWithdraw):
            self.handle_withdraw(state_change)

        elif log.isEnabledFor(logging.ERROR):
            log.error('Unknown state_change', state_change=state_change)

    def handle_tokenadded(self, state_change):
        manager_address = state_change.manager_address
        self.raiden.register_channel_manager(manager_address)

    def handle_channelnew(self, state_change):
        manager_address = state_change.manager_address
        channel_address = state_change.channel_address
        participant1 = state_change.participant1
        participant2 = state_change.participant2

        token_address = self.raiden.manager_to_token[manager_address]
        graph = self.raiden.token_to_channelgraph[token_address]
        graph.add_path(participant1, participant2)

        connection_manager = self.raiden.connection_manager_for_token(token_address)

        is_participant = self.raiden.address in (participant1, participant2)
        is_bootstrap = connection_manager.BOOTSTRAP_ADDR in (participant1, participant2)
        other = participant2 if (participant1 == self.raiden.address) else participant1
        if is_participant:
            self.raiden.register_netting_channel(
                token_address,
                channel_address,
            )
            if not is_bootstrap:
                self.raiden.start_health_check_for(other)
        elif connection_manager.wants_more_channels:
            gevent.spawn(connection_manager.retry_connect)
        else:
            log.info('ignoring new channel, this node is not a participant.')

    def handle_balance(self, state_change):
        channel_address = state_change.channel_address
        token_address = state_change.token_address
        participant_address = state_change.participant_address
        balance = state_change.balance

        graph = self.raiden.token_to_channelgraph[token_address]
        channel = graph.address_to_channel[channel_address]

        channel.state_transition(state_change)

        if channel.contract_balance == 0:
            connection_manager = self.raiden.connection_manager_for_token(
                token_address
            )

            gevent.spawn(
                connection_manager.join_channel,
                participant_address,
                balance
            )

    def handle_closed(self, state_change):
        channel_address = state_change.channel_address
        channel = self.raiden.find_channel_by_address(channel_address)
        channel.state_transition(state_change)

    def handle_settled(self, state_change):
        channel_address = state_change.channel_address
        channel = self.raiden.find_channel_by_address(channel_address)
        channel.state_transition(state_change)

    def handle_withdraw(self, state_change):
        secret = state_change.secret
        self.raiden.register_secret(secret)
