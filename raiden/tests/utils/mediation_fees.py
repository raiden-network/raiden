import pytest

from raiden.tests.utils import factories
from raiden.utils.mediation_fees import prepare_mediation_fee_config
from raiden.utils.typing import ProportionalFeeAmount


@pytest.mark.parametrize("flat_fees", [(42, 21), (43, 21)])
def test_prepare_mediation_fee_config_flat_fee(flat_fees):
    cli_flat_fee, expected_channel_flat_fee = flat_fees
    token_network_address = factories.make_token_network_address()
    fee_config = prepare_mediation_fee_config(
        cli_token_network_to_flat_fee=((token_network_address, cli_flat_fee),),
        proportional_fee=ProportionalFeeAmount(0),
        proportional_imbalance_fee=ProportionalFeeAmount(0),
    )

    assert fee_config.get_flat_fee(token_network_address) == expected_channel_flat_fee


@pytest.mark.parametrize(
    "prop_fees",
    [
        (1_000_000, 1_000_000),  # 100%
        (999_999, 999_000),  # 99.9999%
        (990_000, 900_000),  # 99%
        (100_000, 51317),  # 10%
        (10_000, 5013),  # 1%
        (0, 0),  # 0%
    ],
)
def test_prepare_mediation_fee_config_prop_fee(prop_fees):
    cli_prop_fee, expected_channel_prop_fee = prop_fees
    fee_config = prepare_mediation_fee_config(
        cli_token_network_to_flat_fee=(),
        proportional_fee=ProportionalFeeAmount(cli_prop_fee),
        proportional_imbalance_fee=ProportionalFeeAmount(0),
    )

    assert fee_config.proportional_fee == expected_channel_prop_fee
