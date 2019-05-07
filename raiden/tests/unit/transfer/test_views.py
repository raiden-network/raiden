from raiden.tests.utils import factories
from raiden.transfer.views import filter_channels_by_partneraddress


def test_filter_channels_by_partneraddress_empty(chain_state):
    payment_network_id = factories.make_address()
    token_address = factories.make_address()
    partner_addresses = [factories.make_address(), factories.make_address()]
    assert (
        filter_channels_by_partneraddress(
            chain_state=chain_state,
            payment_network_id=payment_network_id,
            token_address=token_address,
            partner_addresses=partner_addresses,
        )
        == []
    )
