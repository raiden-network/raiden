import logging
import os

import pytest
import structlog

from raiden.exceptions import ConfigurationError
from raiden.log_config import LogFilter, configure_logging


def test_log_filter():
    rules = {"": "INFO"}
    filter_ = LogFilter(rules, default_level="INFO")

    assert filter_.should_log("test", "DEBUG") is False
    assert filter_.should_log("test", "INFO") is True
    assert filter_.should_log("raiden", "DEBUG") is False
    assert filter_.should_log("raiden", "INFO") is True
    assert filter_.should_log("raiden.cli", "DEBUG") is False
    assert filter_.should_log("raiden.cli", "INFO") is True

    rules = {"": "WARN"}
    filter_ = LogFilter(rules, default_level="INFO")

    assert filter_.should_log("test", "INFO") is False
    assert filter_.should_log("test", "WARN") is True
    assert filter_.should_log("raiden", "INFO") is False
    assert filter_.should_log("raiden", "WARN") is True
    assert filter_.should_log("raiden.cli", "INFO") is False
    assert filter_.should_log("raiden.cli", "WARN") is True

    rules = {"test": "WARN"}
    filter_ = LogFilter(rules, default_level="INFO")

    assert filter_.should_log("test", "INFO") is False
    assert filter_.should_log("test", "WARN") is True
    assert filter_.should_log("raiden", "DEBUG") is False
    assert filter_.should_log("raiden", "INFO") is True
    assert filter_.should_log("raiden", "WARN") is True
    assert filter_.should_log("raiden.cli", "DEBUG") is False
    assert filter_.should_log("raiden.cli", "INFO") is True
    assert filter_.should_log("raiden.cli", "WARN") is True

    rules = {"raiden": "DEBUG"}
    filter_ = LogFilter(rules, default_level="INFO")

    assert filter_.should_log("test", "DEBUG") is False
    assert filter_.should_log("test", "INFO") is True
    assert filter_.should_log("raiden", "DEBUG") is True
    assert filter_.should_log("raiden.cli", "DEBUG") is True

    rules = {"raiden.network": "DEBUG"}
    filter_ = LogFilter(rules, default_level="INFO")

    assert filter_.should_log("test", "DEBUG") is False
    assert filter_.should_log("test", "INFO") is True
    assert filter_.should_log("raiden", "DEBUG") is False
    assert filter_.should_log("raiden", "INFO") is True
    assert filter_.should_log("raiden.network", "DEBUG") is True

    rules = {
        "": "WARN",
        "raiden": "DEBUG",
        "raiden.network": "INFO",
        "raiden.network.transport": "DEBUG",
    }
    filter_ = LogFilter(rules, default_level="INFO")

    assert filter_.should_log("raiden.network.transport.matrix", "DEBUG") is True
    assert filter_.should_log("raiden.network.transport", "DEBUG") is True
    assert filter_.should_log("raiden.network", "DEBUG") is False
    assert filter_.should_log("raiden.network", "INFO") is True
    assert filter_.should_log("raiden.network", "INFO") is True
    assert filter_.should_log("raiden", "DEBUG") is True
    assert filter_.should_log("", "DEBUG") is False
    assert filter_.should_log("", "INFO") is False
    assert filter_.should_log("", "WARN") is True
    assert filter_.should_log("other", "DEBUG") is False
    assert filter_.should_log("other", "WARN") is True

    rules = {"raiden": "DEBUG", "raiden.network": "INFO", "raiden.network.transport": "DEBUG"}
    filter_ = LogFilter(rules, default_level="INFO")

    assert filter_.should_log("raiden.network.transport.matrix", "DEBUG") is True
    assert filter_.should_log("raiden.network.transport", "DEBUG") is True
    assert filter_.should_log("raiden.network", "DEBUG") is False
    assert filter_.should_log("raiden.network", "INFO") is True
    assert filter_.should_log("raiden.network", "INFO") is True
    assert filter_.should_log("raiden", "DEBUG") is True
    assert filter_.should_log("", "DEBUG") is False
    assert filter_.should_log("", "INFO") is True
    assert filter_.should_log("", "WARN") is True
    assert filter_.should_log("other", "DEBUG") is False
    assert filter_.should_log("other", "INFO") is True
    assert filter_.should_log("other", "WARN") is True


@pytest.mark.parametrize("module", ["", "raiden", "raiden.network"])
@pytest.mark.parametrize("level", ["DEBUG", "WARNING"])
@pytest.mark.parametrize("logger", ["test", "raiden", "raiden.network"])
@pytest.mark.parametrize("disabled_debug", [True, False])
def test_basic_logging(capsys, module, level, logger, disabled_debug, tmpdir):
    configure_logging(
        {module: level},
        disable_debug_logfile=disabled_debug,
        debug_log_file_path=str(tmpdir / "raiden-debug.log"),
        colorize=False,
    )
    log = structlog.get_logger(logger).bind(foo="bar")
    log.debug("test event", key="value")

    captured = capsys.readouterr()

    no_log = level != "DEBUG" or module not in logger
    if no_log:
        assert captured.err == ""
    else:
        assert "test event" in captured.err
        assert "key=value" in captured.err
        assert "foo=bar" in captured.err


def test_debug_logfile_invalid_dir():
    """Test that providing an invalid directory for the debug logfile throws an error"""
    with pytest.raises(ConfigurationError):
        configure_logging(
            {"": "DEBUG"}, debug_log_file_path=os.path.join("notarealdir", "raiden-debug.log")
        )


def test_redacted_request(capsys, tmpdir):
    configure_logging({"": "DEBUG"}, debug_log_file_path=str(tmpdir / "raiden-debug.log"))
    token = "my_access_token123"

    # use logging, as 'urllib3/requests'
    log = logging.getLogger("urllib3.connectionpool")
    log.debug("Starting new HTTPS connection (1): example.org:443")
    log.debug(f'https://example.org:443 "GET /endpoint?access_token={token} HTTP/1.1" 200 403')

    captured = capsys.readouterr()

    assert token not in captured.err
    assert "access_token=<redacted>" in captured.err


def test_that_secret_is_redacted(capsys, tmpdir):
    configure_logging({"": "DEBUG"}, debug_log_file_path=str(tmpdir / "raiden-debug.log"))

    log = structlog.get_logger("raiden.network.transport.matrix.transport")

    secret = "0x74564b5d217c3430713e7c6b643b5b244c6d617a4e350945303960723a7b2d4c"
    data = f"""{{"secret": "{secret}", "signature": "0x274ec0589b47a85fa8645a4b7fa9f021b3ba7b81e41ab47278c6269089bad7b26f41f233236d994dd86b495791c95e433710365224d390aeb9f7ee427eddb5081b", "message_identifier": "3887369794757038169", "type": "RevealSecret"}}"""  # noqa

    log.debug("Send raw", data=data.replace("\n", "\\n"))

    captured = capsys.readouterr()

    assert secret not in captured.err
    assert '"secret": "<redacted>"' in captured.err
