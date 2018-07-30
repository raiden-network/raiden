import time
import logging
import logging.config
import re
from traceback import TracebackException
from functools import wraps
from typing import Dict, Callable, Pattern, Optional
from cachetools import LRUCache, cachedmethod
from operator import attrgetter

import structlog

DEFAULT_LOG_LEVEL = 'INFO'
MAX_LOG_FILE_SIZE = 5 * 1024 * 1024


def _chain(first_func, *funcs) -> Callable:
    """Chains a give number of functions.
    First function receives all args/kwargs. Its result is passed on as an argument
    to the second one and so on and so forth until all function arguments are used.
    The last result is then returned.
    """
    @wraps(first_func)
    def wrapper(*args, **kwargs):
        result = first_func(*args, **kwargs)
        for func in funcs:
            result = func(result)
        return result
    return wrapper


def _get_log_level(
    module_rules: Dict[str, str],
    logger_module: str,
) -> Optional[str]:
    split = lambda l: l.split('.') if l else list()
    logger = split(logger_module)
    for module in sorted(module_rules.keys(), key=_chain(split, len), reverse=True):
        split_module = split(module)

        if logger[:len(split_module)] == split_module:
            return module_rules[module]


class RaidenFilter(logging.Filter):
    def __init__(self, log_level_config, name=''):
        super().__init__(name)
        self._log_rules = log_level_config
        self._cache = LRUCache(64)

    @cachedmethod(attrgetter('_cache'), key=lambda _, record: (record.name, record.levelname))
    def filter(self, record):
        # this check is needed as the flask logs somehow don't get processed by structlog
        log_level_per_rule = _get_log_level(
            self._log_rules,
            record.name,
        ) or DEFAULT_LOG_LEVEL
        log_level_per_rule_numeric = getattr(logging, log_level_per_rule, logging.DEBUG)
        log_level_event_numeric = record.levelno

        # Propgate the event when the log level is lower than the threshold
        if log_level_event_numeric < log_level_per_rule_numeric:
            return False

        return True


def _get_log_handler(formatter: str, log_file: str) -> Dict:
    if log_file:
        return {
            'file': {
                'class': 'logging.handlers.WatchedFileHandler',
                'filename': log_file,
                'level': 'DEBUG',
                'formatter': formatter,
                'filters': ['log_level_filter'],
            },
        }
    else:
        return {
            'default': {
                'class': 'logging.StreamHandler',
                'level': 'DEBUG',
                'formatter': formatter,
                'filters': ['log_level_filter'],
            },
        }


def _get_log_file_handler() -> Dict:
    time_suffix = time.strftime("%Y-%m-%d_%H-%M-%S")
    return {
        'debug-info': {
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': f'raiden-debug-{time_suffix}.log',
            'level': 'DEBUG',
            'formatter': 'debug',
            'maxBytes': MAX_LOG_FILE_SIZE,
            'backupCount': 1,
            'filters': ['log_level_debug_filter'],
        },
    }


def redactor(blacklist: Dict[Pattern, str]) -> Callable:
    """Returns a function which transforms a str, replacing all matches for its replacement"""
    def processor_wrapper(msg: str) -> str:
        for regex, repl in blacklist.items():
            if repl is None:
                repl = '<redacted>'
            msg = regex.sub(repl, msg)
        return msg
    return processor_wrapper


def _wrap_tracebackexception_format(redact: Callable[[str], str]):
    """Monkey-patch TracebackException.format to redact printed lines"""
    if hasattr(TracebackException, '_orig_format'):
        prev_fmt = TracebackException._orig_format
    else:
        prev_fmt = TracebackException._orig_format = TracebackException.format

    def tracebackexception_format(self, *, chain=True):
        for line in prev_fmt(self, chain=chain):
            yield redact(line)

    TracebackException.format = tracebackexception_format


def configure_logging(
    logger_level_config: Dict[str, str] = None,
    colorize: bool = True,
    log_json: bool = False,
    log_file: str = None,
):
    structlog.reset_defaults()
    if logger_level_config is None:
        logger_level_config = {'': DEFAULT_LOG_LEVEL}
    processors = [
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="%Y-%m-%d %H:%M:%S"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    formatter = 'colorized' if colorize and not log_file else 'plain'
    if log_json:
        formatter = 'json'

    redact = redactor({
        re.compile(r'\b(access_?token=)([a-z0-9_-]+)', re.I): r'\1<redacted>',
    })
    _wrap_tracebackexception_format(redact)

    log_handler = _get_log_handler(
        formatter,
        log_file,
    )
    debug_log_file_handler = _get_log_file_handler()

    combined_log_handlers = {**log_handler, **debug_log_file_handler}

    logging.config.dictConfig(
        {
            'version': 1,
            'disable_existing_loggers': False,
            'filters': {
                'log_level_filter': {
                    '()': RaidenFilter,
                    'log_level_config': logger_level_config,
                },
                'log_level_debug_filter': {
                    '()': RaidenFilter,
                    'log_level_config': {'': DEFAULT_LOG_LEVEL, 'raiden': 'DEBUG'},
                },
            },
            'formatters': {
                'plain': {
                    '()': structlog.stdlib.ProcessorFormatter,
                    'processor': _chain(structlog.dev.ConsoleRenderer(colors=False), redact),
                    'foreign_pre_chain': processors,
                },
                'json': {
                    '()': structlog.stdlib.ProcessorFormatter,
                    'processor': _chain(structlog.processors.JSONRenderer(), redact),
                    'foreign_pre_chain': processors,
                },
                'colorized': {
                    '()': structlog.stdlib.ProcessorFormatter,
                    'processor': _chain(structlog.dev.ConsoleRenderer(colors=True), redact),
                    'foreign_pre_chain': processors,
                },
                'debug': {
                    '()': structlog.stdlib.ProcessorFormatter,
                    'processor': _chain(structlog.dev.ConsoleRenderer(colors=False), redact),
                    'foreign_pre_chain': processors,
                },
            },
            'handlers': combined_log_handlers,
            'loggers': {
                '': {
                    'handlers': list(combined_log_handlers.keys()),
                    'propagate': True,
                },
            },
        },
    )
    structlog.configure(
        processors=processors + [
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # set raiden logging level to DEBUG, to be able to intercept all messages,
    # which should then be filtered by the specific filters
    structlog.get_logger('').setLevel('DEBUG')
    structlog.get_logger('raiden').setLevel('DEBUG')
