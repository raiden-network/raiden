import pytest
from raiden.tests.utils.detect_failure import raise_on_failure


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
@pytest.mark.parametrize("enable_rest_api", [True])
def test_get_empty_notifications(client, api_server_test_instance):
    response = client.get("/api/v1/notifications")
    assert response.get_json() == []
