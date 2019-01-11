from time import time
from unittest.mock import patch

import pytest
import web3
from requests.exceptions import ConnectionError
from web3.providers import HTTPProvider

from pathfinding_service.middleware import http_retry_with_backoff_middleware


@patch('web3.providers.rpc.make_post_request')
def test_retries(make_post_request_mock):

    # use short backoff times to make the test run quickly
    def quick_retry_middleware(make_request, web3):
        return http_retry_with_backoff_middleware(
            make_request,
            web3,
            retries=5,
            first_backoff=0.01,
        )

    provider = HTTPProvider()
    provider.middlewares.replace(
        'http_retry_request',
        quick_retry_middleware,
    )
    w3 = web3.Web3(provider)

    # log the time since start each time the mock is called
    start_time = time()
    retry_times = []

    def side_effect(*args, **kwargs):
        retry_times.append(time() - start_time)
        raise ConnectionError
    make_post_request_mock.side_effect = side_effect

    # the call must fail after the number of retries is exceeded
    with pytest.raises(ConnectionError):
        w3.eth.blockNumber()

    # check timings
    assert make_post_request_mock.call_count == 5
    expected_times = [
        0,
        0.01,
        0.01 + 0.02,
        0.01 + 0.02 + 0.04,
        0.01 + 0.02 + 0.04 + 0.08,
    ]
    assert retry_times == pytest.approx(expected_times, abs=0.002, rel=0.3)

    # try again to make sure that each request starts with a clean backoff
    start_time = time()
    retry_times = []
    with pytest.raises(ConnectionError):
        w3.eth.blockNumber()
    assert retry_times == pytest.approx(expected_times, abs=0.002, rel=0.3)
