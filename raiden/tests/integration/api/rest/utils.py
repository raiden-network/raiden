import json
from http import HTTPStatus

from eth_utils import to_bytes, to_canonical_address
from flask import url_for

from raiden.constants import SECRET_LENGTH
from raiden.utils.secrethash import sha256_secrethash
from raiden.utils.typing import Secret


def get_json_response(response):
    """
    Utility function to deal with JSON responses.
    requests's `.json` can fail when simplejson is installed. See
    https://github.com/raiden-network/raiden/issues/4174
    """
    return json.loads(response.content)


def assert_no_content_response(response):
    assert (
        response is not None
        and response.text == ""
        and response.status_code == HTTPStatus.NO_CONTENT
    )


def assert_response_with_code(response, status_code):
    assert response is not None and response.status_code == status_code


def assert_response_with_error(response, status_code):
    json_response = get_json_response(response)
    assert (
        response is not None
        and response.status_code == status_code
        and "errors" in json_response
        and json_response["errors"] != ""
    )


def assert_proper_response(response, status_code=HTTPStatus.OK):
    assert (
        response is not None
        and response.status_code == status_code
        and response.headers["Content-Type"] == "application/json"
    ), response.text


def assert_payment_secret_and_hash(response, payment):
    # make sure that payment key/values are part of the response.
    assert len(response) == 7
    assert "secret" in response
    assert "secret_hash" in response

    secret = Secret(to_bytes(hexstr=response["secret"]))
    assert len(secret) == SECRET_LENGTH
    assert payment["amount"] == response["amount"]

    assert to_bytes(hexstr=response["secret_hash"]) == sha256_secrethash(secret)


def assert_payment_conflict(responses):
    assert all(response is not None for response in responses)
    assert any(
        resp.status_code == HTTPStatus.CONFLICT
        and get_json_response(resp)["errors"] == "Another payment with the same id is in flight"
        for resp in responses
    )


def api_url_for(api_server, endpoint, **kwargs):
    # url_for() expects binary address so we have to convert here
    for key, val in kwargs.items():
        if isinstance(val, str) and val.startswith("0x"):
            kwargs[key] = to_canonical_address(val)
    with api_server.flask_app.app_context():
        return url_for(f"v1_resources.{endpoint}", **kwargs)
