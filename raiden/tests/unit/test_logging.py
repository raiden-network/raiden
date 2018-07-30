import logging
import traceback

import structlog
import pytest

from raiden.log_config import configure_logging


@pytest.mark.parametrize('module', ['', 'raiden', 'raiden.network'])
@pytest.mark.parametrize('level', ['DEBUG', 'WARNING'])
@pytest.mark.parametrize('logger', ['test', 'raiden', 'raiden.network'])
def test_basic_logging(capsys, module, level, logger):
    configure_logging({module: level})
    log = structlog.get_logger(logger).bind(foo='bar')
    log.debug('test event', key='value')

    captured = capsys.readouterr()

    no_log = level != 'DEBUG' or module not in logger
    if no_log:
        assert captured.err == ''
    else:
        assert 'test event' in captured.err
        assert 'key=value' in captured.err
        assert 'foo=bar' in captured.err


def test_redacted_request(capsys):
    configure_logging({'': 'DEBUG'})
    token = 'my_access_token123'

    # use logging, as 'urllib3/requests'
    log = logging.getLogger('urllib3.connectionpool')
    log.debug('Starting new HTTPS connection (1): example.org:443')
    log.debug(f'https://example.org:443 "GET /endpoint?access_token={token} HTTP/1.1" 200 403')

    captured = capsys.readouterr()

    assert token not in captured.err
    assert 'access_token=<redacted>' in captured.err


def test_redacted_traceback(capsys):
    configure_logging({'': 'DEBUG'})

    token = 'my_access_token123'

    try:
        assert False, f'Failed acessing /endpoint?accessToken={token}'
    except AssertionError:
        traceback.print_exc()

    captured = capsys.readouterr()

    assert token not in captured.err
    assert 'accessToken=<redacted>' in captured.err
