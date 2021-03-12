import random

import pytest
from faker import Faker

from raiden.api.objects import Notification
from raiden.tests.utils.detect_failure import raise_on_failure

fake = Faker()
notifications_endpoint = "/api/v1/notifications"


@raise_on_failure
@pytest.mark.parametrize("enable_rest_api", [True])
def test_get_empty_notifications(client, api_server_test_instance):
    assert api_server_test_instance
    response = client.get(notifications_endpoint)
    assert response.get_json() == []


@raise_on_failure
@pytest.mark.parametrize("enable_rest_api", [True])
def test_get_notification(client, api_server_test_instance):
    notification = create_notification(api_server_test_instance)
    response = client.get(notifications_endpoint)
    assert response.get_json() == [
        {
            "id": notification.id,
            "summary": notification.summary,
            "body": notification.body,
            "urgency": notification.urgency,
        }
    ]


@raise_on_failure
@pytest.mark.parametrize("enable_rest_api", [True])
def test_get_many_notifications(client, api_server_test_instance):
    total_notifications = 3
    for _ in range(total_notifications):
        create_notification(api_server_test_instance)

    response = client.get(notifications_endpoint)
    assert len(response.get_json()) == total_notifications


@raise_on_failure
@pytest.mark.parametrize("enable_rest_api", [True])
def test_get_notifications_empty_queue(client, api_server_test_instance):
    create_notification(api_server_test_instance)

    response = client.get(notifications_endpoint)
    assert response.get_json() != []

    response = client.get(notifications_endpoint)
    assert response.get_json() == []


@raise_on_failure
@pytest.mark.parametrize("enable_rest_api", [True])
def test_notifications_with_same_id_are_overwritten(client, api_server_test_instance):
    for i in range(3):
        create_notification(
            api_server_test_instance, notification_id="same_id", summary=f"summary_{i}"
        )

    response = client.get(notifications_endpoint)
    response = response.get_json()
    assert len(response) == 1
    assert response[0]["summary"] == "summary_2"


def create_notification(api_server, notification_id=None, summary=None, body=None, urgency=None):
    notification_opts = {
        "id": notification_id or fake.bs(),
        "summary": summary or fake.text(max_nb_chars=20),
        "body": body or fake.sentence(nb_words=7),
        "urgency": urgency or random.choice(["low", "normal", "critical"]),
    }
    notification = Notification(**notification_opts)
    api_server.rest_api.raiden_api.raiden.add_notification(notification)
    return notification
