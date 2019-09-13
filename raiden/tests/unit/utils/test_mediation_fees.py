from math import isclose

import pytest

from raiden.tests.utils import factories
from raiden.utils.mediation_fees import prepare_mediation_fee_config
from raiden.utils.typing import FeeAmount, ProportionalFeeAmount


@pytest.mark.parametrize(
    "cli_flat_fee, expected_channel_flat_fee",
    [(FeeAmount(42), FeeAmount(21)), (FeeAmount(43), FeeAmount(21))],
)
def test_prepare_mediation_fee_config_flat_fee(cli_flat_fee, expected_channel_flat_fee):
    token_network_address = factories.make_token_network_address()
    fee_config = prepare_mediation_fee_config(
        cli_token_network_to_flat_fee=((token_network_address, cli_flat_fee),),
        proportional_fee=ProportionalFeeAmount(0),
        proportional_imbalance_fee=ProportionalFeeAmount(0),
    )

    assert fee_config.get_flat_fee(token_network_address) == expected_channel_flat_fee


@pytest.mark.parametrize(
    "cli_prop_fee",
    [
        1_000_000,  # 100%
        999_999,  # 99.9999%
        990_000,  # 99%
        100_000,  # 10%
        10_000,  # 1%
        0,  # 0%
    ],
)
def test_prepare_mediation_fee_config_prop_fee(cli_prop_fee):
    fee_config = prepare_mediation_fee_config(
        cli_token_network_to_flat_fee=(),
        proportional_fee=ProportionalFeeAmount(cli_prop_fee),
        proportional_imbalance_fee=ProportionalFeeAmount(0),
    )

    cli_prop_fee_ratio = cli_prop_fee / 1e6
    channel_prop_fee_ratio = fee_config.proportional_fee / 1e6

    assert isclose(
        1 + cli_prop_fee_ratio,
        1 + channel_prop_fee_ratio + channel_prop_fee_ratio * (1 + cli_prop_fee_ratio),
        rel_tol=1e-6,
    )
