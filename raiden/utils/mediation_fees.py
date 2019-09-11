from math import sqrt

from raiden.settings import MediationFeeConfig
from raiden.transfer.channel import get_capacity
from raiden.transfer.mediated_transfer.mediation_fee import calculate_imbalance_fees
from raiden.transfer.state import FeeScheduleState, NettingChannelState
from raiden.transfer.state_change import ActionChannelUpdateFee
from raiden.utils.typing import Dict, FeeAmount, ProportionalFeeAmount, TokenNetworkAddress, Tuple


def actionchannelupdatefee_from_channelstate(
    channel_state: NettingChannelState,
    flat_fee: FeeAmount,
    proportional_fee: ProportionalFeeAmount,
    proportional_imbalance_fee: ProportionalFeeAmount,
) -> ActionChannelUpdateFee:
    imbalance_penalty = calculate_imbalance_fees(
        channel_capacity=get_capacity(channel_state),
        proportional_imbalance_fee=proportional_imbalance_fee,
    )

    return ActionChannelUpdateFee(
        canonical_identifier=channel_state.canonical_identifier,
        fee_schedule=FeeScheduleState(
            flat=flat_fee, proportional=proportional_fee, imbalance_penalty=imbalance_penalty
        ),
    )


def prepare_mediation_fee_config(
    cli_token_network_to_flat_fee: Tuple[Tuple[TokenNetworkAddress, FeeAmount], ...],
    proportional_fee: ProportionalFeeAmount,
    proportional_imbalance_fee: ProportionalFeeAmount,
) -> MediationFeeConfig:
    """ Converts the mediation fee CLI args to proper per-channel
    mediation fees. """
    # Store the flat fee settings for the given token networks
    # The given flat fee is for the whole mediation, but that includes two channels.
    # Therefore divide by 2 here.
    token_network_to_flat_fee: Dict[TokenNetworkAddress, FeeAmount] = {
        address: FeeAmount(fee // 2) for address, fee in cli_token_network_to_flat_fee
    }
    # Given prop. fee also counts per mediation, therefore it needs to be adjusted on
    # a per-channel basis:
    # x * (1 - p) * (1 - p) = x * (1 - q)
    # where
    #    x = payment amount
    #    q = cli proportional fee
    #    p = per channel proportional fee
    # Leads to: p = 1 - sqrt(1 - q)
    proportional_fee_ratio = proportional_fee / 1e6
    channel_prop_fee_ratio = 1 - sqrt(1 - proportional_fee_ratio)
    channel_prop_fee = round(channel_prop_fee_ratio * 1e6)
    return MediationFeeConfig(
        token_network_to_flat_fee=token_network_to_flat_fee,
        proportional_fee=ProportionalFeeAmount(channel_prop_fee),
        proportional_imbalance_fee=proportional_imbalance_fee,
    )
