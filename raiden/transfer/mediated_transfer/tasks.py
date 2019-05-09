from dataclasses import dataclass, field

from raiden.transfer.identifiers import CanonicalIdentifier
from raiden.transfer.mediated_transfer.state import (
    InitiatorPaymentState,
    MediatorTransferState,
    TargetTransferState,
)
from raiden.transfer.state import TransferTask
from raiden.utils.typing import ChannelID, TokenNetworkID


@dataclass
class InitiatorTask(TransferTask):
    token_network_identifier: TokenNetworkID
    manager_state: InitiatorPaymentState = field(repr=False)


@dataclass
class MediatorTask(TransferTask):
    token_network_identifier: TokenNetworkID
    mediator_state: MediatorTransferState = field(repr=False)


@dataclass
class TargetTask(TransferTask):
    canonical_identifier: CanonicalIdentifier
    target_state: TargetTransferState = field(repr=False)

    @property
    def token_network_identifier(self) -> TokenNetworkID:
        return TokenNetworkID(self.canonical_identifier.token_network_address)

    @property
    def channel_identifier(self) -> ChannelID:
        return self.canonical_identifier.channel_identifier
