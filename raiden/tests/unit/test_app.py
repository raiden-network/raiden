from raiden.ui.app import rpc_normalized_endpoint


def test_rpc_normalized_endpoint():
    """Test that the rpc_normalized_endpoint function works as expected"""
    # Infura should always be forced to https scheme
    res = rpc_normalized_endpoint("goerli.infura.io/v3/11111111111111111111111111111111")
    assert res == "https://goerli.infura.io/v3/11111111111111111111111111111111"
    res = rpc_normalized_endpoint("http://goerli.infura.io/v3/11111111111111111111111111111111")
    assert res == "https://goerli.infura.io/v3/11111111111111111111111111111111"
    res = rpc_normalized_endpoint("https://goerli.infura.io/v3/11111111111111111111111111111111")
    assert res == "https://goerli.infura.io/v3/11111111111111111111111111111111"

    # if the endpoint does not have a scheme, append http scheme
    res = rpc_normalized_endpoint("//127.0.0.1:5454")
    assert res == "http://127.0.0.1:5454"
    res = rpc_normalized_endpoint("http://127.0.0.1:5454")
    assert res == "http://127.0.0.1:5454"
