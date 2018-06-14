from eth_utils import keccak


def test_secret_registry(secret_registry_proxy, get_random_bytes):
    #  register secret
    secret = get_random_bytes(32)
    secret_registry_proxy.register_secret(secret)

    # check if event is raised
    event_filter = secret_registry_proxy.secret_registered_filter()
    logs = event_filter.get_all_entries()
    assert len(logs) == 1
    decoded_event = secret_registry_proxy.proxy.decode_event(logs[0])
    data = keccak(secret)
    assert decoded_event['args']['secrethash'] == data
    # check if registration block matches
    block = secret_registry_proxy.register_block_by_secrethash(data)
    assert logs[0]['blockNumber'] == block

    #  test non-existing secret
    assert 0 == secret_registry_proxy.register_block_by_secrethash(b'\x11' * 32)
