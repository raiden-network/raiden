import logging
import traceback

import pytest
import structlog

from raiden.log_config import LogFilter, configure_logging


def test_log_filter():
    rules = {'': 'INFO'}
    filter = LogFilter(rules, default_level='INFO')

    assert filter.should_log('test', 'DEBUG') is False
    assert filter.should_log('test', 'INFO') is True
    assert filter.should_log('raiden', 'DEBUG') is False
    assert filter.should_log('raiden', 'INFO') is True
    assert filter.should_log('raiden.cli', 'DEBUG') is False
    assert filter.should_log('raiden.cli', 'INFO') is True

    rules = {'': 'WARN'}
    filter = LogFilter(rules, default_level='INFO')

    assert filter.should_log('test', 'INFO') is False
    assert filter.should_log('test', 'WARN') is True
    assert filter.should_log('raiden', 'INFO') is False
    assert filter.should_log('raiden', 'WARN') is True
    assert filter.should_log('raiden.cli', 'INFO') is False
    assert filter.should_log('raiden.cli', 'WARN') is True

    rules = {'test': 'WARN'}
    filter = LogFilter(rules, default_level='INFO')

    assert filter.should_log('test', 'INFO') is False
    assert filter.should_log('test', 'WARN') is True
    assert filter.should_log('raiden', 'DEBUG') is False
    assert filter.should_log('raiden', 'INFO') is True
    assert filter.should_log('raiden', 'WARN') is True
    assert filter.should_log('raiden.cli', 'DEBUG') is False
    assert filter.should_log('raiden.cli', 'INFO') is True
    assert filter.should_log('raiden.cli', 'WARN') is True

    rules = {'raiden': 'DEBUG'}
    filter = LogFilter(rules, default_level='INFO')

    assert filter.should_log('test', 'DEBUG') is False
    assert filter.should_log('test', 'INFO') is True
    assert filter.should_log('raiden', 'DEBUG') is True
    assert filter.should_log('raiden.cli', 'DEBUG') is True

    rules = {'raiden.network': 'DEBUG'}
    filter = LogFilter(rules, default_level='INFO')

    assert filter.should_log('test', 'DEBUG') is False
    assert filter.should_log('test', 'INFO') is True
    assert filter.should_log('raiden', 'DEBUG') is False
    assert filter.should_log('raiden', 'INFO') is True
    assert filter.should_log('raiden.network', 'DEBUG') is True

    rules = {
        '': 'WARN',
        'raiden': 'DEBUG',
        'raiden.network': 'INFO',
        'raiden.network.transport': 'DEBUG',
    }
    filter = LogFilter(rules, default_level='INFO')

    assert filter.should_log('raiden.network.transport.matrix', 'DEBUG') is True
    assert filter.should_log('raiden.network.transport', 'DEBUG') is True
    assert filter.should_log('raiden.network', 'DEBUG') is False
    assert filter.should_log('raiden.network', 'INFO') is True
    assert filter.should_log('raiden.network', 'INFO') is True
    assert filter.should_log('raiden', 'DEBUG') is True
    assert filter.should_log('', 'DEBUG') is False
    assert filter.should_log('', 'INFO') is False
    assert filter.should_log('', 'WARN') is True
    assert filter.should_log('other', 'DEBUG') is False
    assert filter.should_log('other', 'WARN') is True

    rules = {
        'raiden': 'DEBUG',
        'raiden.network': 'INFO',
        'raiden.network.transport': 'DEBUG',
    }
    filter = LogFilter(rules, default_level='INFO')

    assert filter.should_log('raiden.network.transport.matrix', 'DEBUG') is True
    assert filter.should_log('raiden.network.transport', 'DEBUG') is True
    assert filter.should_log('raiden.network', 'DEBUG') is False
    assert filter.should_log('raiden.network', 'INFO') is True
    assert filter.should_log('raiden.network', 'INFO') is True
    assert filter.should_log('raiden', 'DEBUG') is True
    assert filter.should_log('', 'DEBUG') is False
    assert filter.should_log('', 'INFO') is True
    assert filter.should_log('', 'WARN') is True
    assert filter.should_log('other', 'DEBUG') is False
    assert filter.should_log('other', 'INFO') is True
    assert filter.should_log('other', 'WARN') is True


@pytest.mark.parametrize('module', ['', 'raiden', 'raiden.network'])
@pytest.mark.parametrize('level', ['DEBUG', 'WARNING'])
@pytest.mark.parametrize('logger', ['test', 'raiden', 'raiden.network'])
@pytest.mark.parametrize('disabled_debug', [True, False])
def test_basic_logging(capsys, module, level, logger, disabled_debug):
    configure_logging({module: level}, disable_debug_logfile=disabled_debug)
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
