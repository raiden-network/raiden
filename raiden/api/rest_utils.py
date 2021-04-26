import json
from http import HTTPStatus

import structlog
from flask import Response, make_response

from raiden.utils.typing import Any, Callable

log = structlog.get_logger(__name__)


ERROR_STATUS_CODES = [
    HTTPStatus.FORBIDDEN,
    HTTPStatus.CONFLICT,
    HTTPStatus.PAYMENT_REQUIRED,
    HTTPStatus.BAD_REQUEST,
    HTTPStatus.NOT_FOUND,
    HTTPStatus.NOT_IMPLEMENTED,
    HTTPStatus.INTERNAL_SERVER_ERROR,
    HTTPStatus.SERVICE_UNAVAILABLE,
]


def api_response(result: Any, status_code: HTTPStatus = HTTPStatus.OK) -> Response:
    if status_code == HTTPStatus.NO_CONTENT:
        assert not result, "Provided 204 response with non-zero length response"
        data = ""
    else:
        data = json.dumps(result)

    log.debug("Request successful", response=result, status_code=status_code)
    response = make_response(
        (data, status_code, {"mimetype": "application/json", "Content-Type": "application/json"})
    )
    return response


def api_error(errors: Any, status_code: HTTPStatus) -> Response:
    assert status_code in ERROR_STATUS_CODES, "Programming error, unexpected error status code"
    log.error("Error processing request", errors=errors, status_code=status_code)
    response = make_response(
        (
            json.dumps(dict(errors=errors)),
            status_code,
            {"mimetype": "application/json", "Content-Type": "application/json"},
        )
    )
    return response


def if_api_available(method: Callable) -> Callable:
    """Decorator for resource methods which only work if the API is fully available."""

    def decorated(self, *args, **kwargs):  # type: ignore
        if not self.rest_api.available:
            msg = "Service unavailable. Try again later."
            return api_error(msg, HTTPStatus.SERVICE_UNAVAILABLE)

        return method(self, *args, **kwargs)

    return decorated
