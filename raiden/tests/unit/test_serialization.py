import pytest
import cPickle

from raiden.api.python import RaidenAPI


@pytest.mark.parametrize('number_of_tokens', [1])
def test_channel_serialization(
    raiden_network,
    token_addresses,
):
    token_address = token_addresses[0]
    app = raiden_network[0]
    api = RaidenAPI(app.raiden)
    channel = api.get_channel_list(token_address=token_address)[0]
    serialized = channel.serialize()
    pickled = cPickle.dumps(serialized)
    unpickled = cPickle.loads(pickled)
    deserialized = unpickled.to_channel_instance()
    assert deserialized
