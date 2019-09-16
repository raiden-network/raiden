from raiden.settings import MediationFeeConfig
from raiden.utils.typing import Dict, FeeAmount, ProportionalFeeAmount, TokenNetworkAddress, Tuple


def ppm_fee_per_channel(per_hop_fee: ProportionalFeeAmount) -> ProportionalFeeAmount:
    """
    Converts proportional-fee-per-mediation into proportional-fee-per-channel

    Input and output are given in parts-per-million (ppm).

    See https://raiden-network-specification.readthedocs.io/en/latest/mediation_fees.html
    #converting-per-hop-proportional-fees-in-per-channel-proportional-fees
    for how to get to this formula.
    """
    per_hop_ratio = per_hop_fee / 1e6
    return ProportionalFeeAmount(round(per_hop_ratio / (per_hop_ratio + 2) * 1e6))


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
    channel_prop_fee = ppm_fee_per_channel(proportional_fee)
    return MediationFeeConfig(
        token_network_to_flat_fee=token_network_to_flat_fee,
        proportional_fee=ProportionalFeeAmount(channel_prop_fee),
        proportional_imbalance_fee=proportional_imbalance_fee,
    )
