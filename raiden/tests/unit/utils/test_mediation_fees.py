from math import isclose

import pytest

from raiden.tests.utils import factories
from raiden.tests.utils.factories import (
    CanonicalIdentifierProperties,
    NettingChannelEndStateProperties,
    NettingChannelStateProperties,
    make_channel_set,
)
from raiden.tests.utils.mediation_fees import get_initial_amount_for_amount_after_fees
from raiden.transfer.mediated_transfer.mediation_fee import FeeScheduleState
from raiden.utils.mediation_fees import ppm_fee_per_channel, prepare_mediation_fee_config
from raiden.utils.typing import (
    ChannelID,
    FeeAmount,
    List,
    PaymentAmount,
    PaymentWithFeeAmount,
    ProportionalFeeAmount,
    TokenAmount,
)


@pytest.mark.parametrize(
    "cli_flat_fee, expected_channel_flat_fee",
    [(FeeAmount(42), FeeAmount(21)), (FeeAmount(43), FeeAmount(21))],
)
def test_prepare_mediation_fee_config_flat_fee(cli_flat_fee, expected_channel_flat_fee):
    token_address = factories.make_token_address()
    fee_config = prepare_mediation_fee_config(
        cli_token_to_flat_fee=((token_address, cli_flat_fee),),
        cli_token_to_proportional_fee=((token_address, ProportionalFeeAmount(0)),),
        cli_token_to_proportional_imbalance_fee=((token_address, ProportionalFeeAmount(0)),),
        cli_cap_mediation_fees=False,
    )

    assert fee_config.get_flat_fee(token_address) == expected_channel_flat_fee
    assert fee_config.cap_mediation_fees is False


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
    token_address = factories.make_token_address()
    fee_config = prepare_mediation_fee_config(
        cli_token_to_flat_fee=(),
        cli_token_to_proportional_fee=((token_address, ProportionalFeeAmount(cli_prop_fee)),),
        cli_token_to_proportional_imbalance_fee=((token_address, ProportionalFeeAmount(0)),),
        cli_cap_mediation_fees=False,
    )

    cli_prop_fee_ratio = cli_prop_fee / 1e6
    channel_prop_fee_ratio = fee_config.get_proportional_fee(token_address) / 1e6

    assert isclose(
        1 + cli_prop_fee_ratio,
        1 + channel_prop_fee_ratio + channel_prop_fee_ratio * (1 + cli_prop_fee_ratio),
        rel_tol=1e-6,
    )


@pytest.mark.parametrize(
    "flat_fee, prop_fee, balance, final_amount, initial_amount, expected_fees",
    [(1, 0, 100, 50, 52, [2]), (10, 0, 100, 50, 70, [20]), (0, 100_000, 1000, 100, 110, [10])],
)
def test_get_initial_payment_for_final_target_amount(
    flat_fee: FeeAmount,
    prop_fee: ProportionalFeeAmount,
    balance: TokenAmount,
    final_amount: PaymentAmount,
    initial_amount: PaymentWithFeeAmount,
    expected_fees: List[FeeAmount],
):
    prop_fee = ppm_fee_per_channel(prop_fee)
    channel_set = make_channel_set(
        [
            NettingChannelStateProperties(
                canonical_identifier=factories.create(
                    CanonicalIdentifierProperties(channel_identifier=ChannelID(1))
                ),
                our_state=NettingChannelEndStateProperties(balance=TokenAmount(0)),
                partner_state=NettingChannelEndStateProperties(balance=balance),
                fee_schedule=FeeScheduleState(flat=flat_fee, proportional=prop_fee),
            ),
            NettingChannelStateProperties(
                canonical_identifier=factories.create(
                    CanonicalIdentifierProperties(channel_identifier=ChannelID(2))
                ),
                our_state=NettingChannelEndStateProperties(balance=balance),
                partner_state=NettingChannelEndStateProperties(balance=TokenAmount(0)),
                fee_schedule=FeeScheduleState(flat=flat_fee, proportional=prop_fee),
            ),
        ]
    )

    calculation = get_initial_amount_for_amount_after_fees(
        amount_after_fees=final_amount,
        channels=[(channel_set.channels[0], channel_set.channels[1])],
    )

    assert calculation is not None
    assert calculation.total_amount == initial_amount
    assert calculation.mediation_fees == expected_fees
