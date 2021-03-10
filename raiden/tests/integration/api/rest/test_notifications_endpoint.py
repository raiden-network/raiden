from raiden.tests.utils.detect_failure import raise_on_failure


@raise_on_failure
def test_get_empty_notifications(client):
    response = client.get("/notifications")
    assert response.get_json() == []
