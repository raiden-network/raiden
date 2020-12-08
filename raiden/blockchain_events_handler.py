from typing import TYPE_CHECKING

from raiden.transfer.architecture import StateChange
from raiden.transfer.state_change import ContractReceiveChannelNew
from raiden.utils.typing import MYPY_ANNOTATION

if TYPE_CHECKING:
    # pylint: disable=unused-import
    from raiden.raiden_service import RaidenService  # noqa: F401


def after_new_channel_start_healthcheck(
    raiden: "RaidenService", channelnew: ContractReceiveChannelNew
) -> None:
    """Start connection healthcheck once a new channel is opened."""
    partner_address = channelnew.channel_state.partner_state.address
    raiden.async_start_health_check_for(partner_address)


def after_blockchain_statechange(raiden: "RaidenService", state_change: StateChange) -> None:
    if type(state_change) == ContractReceiveChannelNew:
        assert isinstance(state_change, ContractReceiveChannelNew), MYPY_ANNOTATION
        after_new_channel_start_healthcheck(raiden, state_change)
