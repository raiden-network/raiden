from raiden.transfer.architecture import State
from raiden.transfer.identifiers import CanonicalIdentifier
from raiden.transfer.mediated_transfer.state import (
    InitiatorPaymentState,
    MediatorTransferState,
    TargetTransferState,
)
from raiden.utils.typing import TYPE_CHECKING, ChannelID, TokenNetworkID

if TYPE_CHECKING:
    from dataclasses import dataclass, field
else:
    from raiden.storage.serialization import dataclass, field


@dataclass
class TransferTask(State):
    # TODO: When we turn these into dataclasses it would be a good time to move common attributes
    # of all transfer tasks like the `token_network_identifier` into the common subclass
    pass


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
