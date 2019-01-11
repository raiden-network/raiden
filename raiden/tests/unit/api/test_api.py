from raiden.transfer.views import list_channelstate_for_tokennetwork


def test_list_channelstate_for_tokennetwork(
        chain_state,
        token_network_state,
        payment_network_id,
        token_id,
):
    """Regression test for https://github.com/raiden-network/raiden/issues/3257"""
    token_address = token_id
    result = list_channelstate_for_tokennetwork(
        chain_state=chain_state,
        payment_network_id=payment_network_id,
        token_address=token_address,
    )
    assert isinstance(result, list)
