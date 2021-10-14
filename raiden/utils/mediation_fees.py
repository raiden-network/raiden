from fractions import Fraction

from raiden.constants import DAI_TOKEN_ADDRESS, WETH_TOKEN_ADDRESS
from raiden.settings import DEFAULT_DAI_FLAT_FEE, DEFAULT_WETH_FLAT_FEE, MediationFeeConfig
from raiden.utils.typing import Dict, FeeAmount, ProportionalFeeAmount, TokenAddress, Tuple


def ppm_fee_per_channel(per_hop_fee: ProportionalFeeAmount) -> ProportionalFeeAmount:
    """
    Converts proportional-fee-per-mediation into proportional-fee-per-channel

    Input and output are given in parts-per-million (ppm).

    See https://raiden-network-specification.readthedocs.io/en/latest/mediation_fees.html
    #converting-per-hop-proportional-fees-in-per-channel-proportional-fees
    for how to get to this formula.
    """
    per_hop_ratio = Fraction(per_hop_fee, 10 ** 6)
    return ProportionalFeeAmount(round(per_hop_ratio / (per_hop_ratio + 2) * 10 ** 6))


def prepare_mediation_fee_config(
    cli_token_to_flat_fee: Tuple[Tuple[TokenAddress, FeeAmount], ...],
    cli_token_to_proportional_fee: Tuple[Tuple[TokenAddress, ProportionalFeeAmount], ...],
    cli_token_to_proportional_imbalance_fee: Tuple[
        Tuple[TokenAddress, ProportionalFeeAmount], ...
    ],
    cli_cap_mediation_fees: bool,
) -> MediationFeeConfig:
    """Converts the mediation fee CLI args to proper per-channel
    mediation fees."""
    tn_to_flat_fee: Dict[TokenAddress, FeeAmount] = {
        # Add the defaults for flat fees for DAI/WETH
        WETH_TOKEN_ADDRESS: FeeAmount(DEFAULT_WETH_FLAT_FEE // 2),
        DAI_TOKEN_ADDRESS: FeeAmount(DEFAULT_DAI_FLAT_FEE // 2),
    }

    # Store the flat fee settings for the given token addresses
    # The given flat fee is for the whole mediation, but that includes two channels.
    # Therefore divide by 2 here.
    for address, fee in cli_token_to_flat_fee:
        tn_to_flat_fee[address] = FeeAmount(fee // 2)

    tn_to_proportional_fee: Dict[TokenAddress, ProportionalFeeAmount] = {
        address: ppm_fee_per_channel(prop_fee)
        for address, prop_fee in cli_token_to_proportional_fee
    }

    tn_to_proportional_imbalance_fee: Dict[TokenAddress, ProportionalFeeAmount] = {
        address: prop_fee for address, prop_fee in cli_token_to_proportional_imbalance_fee
    }

    return MediationFeeConfig(
        token_to_flat_fee=tn_to_flat_fee,
        token_to_proportional_fee=tn_to_proportional_fee,
        token_to_proportional_imbalance_fee=tn_to_proportional_imbalance_fee,
        cap_mediation_fees=cli_cap_mediation_fees,
    )
