import logging
import logging.config
import os
import re
import sys
from functools import wraps
from traceback import TracebackException
from typing import Callable, Dict, List, Pattern, Tuple

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


class LogFilter:
    """ Utility for filtering log records on module level rules """

    def __init__(self, config: Dict[str, int], default_level: str):
        """ Initializes a new `LogFilter`

        Args:
            config: Dictionary mapping module names to logging level
            default_level: The default logging level
        """
        self._should_log = {}
        # the empty module is not matched, so set it here
        self._default_level = config.get('', default_level)
        self._log_rules = [
            (logger.split('.') if logger else list(), level)
            for logger, level in config.items()
        ]

    def _match_list(
        self,
        module_rule: Tuple[List[str], str],
        logger_name: str,
    ) -> Tuple[int, str]:
        logger_modules_split = logger_name.split('.') if logger_name else []

        modules_split: List[str] = module_rule[0]
        level: str = module_rule[1]

        if logger_modules_split == modules_split:
            return sys.maxsize, level
        else:
            num_modules = len(modules_split)
            if logger_modules_split[:num_modules] == modules_split:
                return num_modules, level
            else:
                return 0, None

    def _get_log_level(self, logger_name: str) -> str:
        best_match_length = 0
        best_match_level = self._default_level
        for module in self._log_rules:
            match_length, level = self._match_list(module, logger_name)

            if match_length > best_match_length:
                best_match_length = match_length
                best_match_level = level

        return best_match_level

    def should_log(self, logger_name: str, level: str) -> bool:
        """ Returns if a message for the logger should be logged. """
        if (logger_name, level) not in self._should_log:
            log_level_per_rule = self._get_log_level(logger_name)
            log_level_per_rule_numeric = getattr(logging, log_level_per_rule.upper(), 10)
            log_level_event_numeric = getattr(logging, level.upper(), 10)

            should_log = log_level_event_numeric >= log_level_per_rule_numeric
            self._should_log[(logger_name, level)] = should_log
        return self._should_log[(logger_name, level)]


class RaidenFilter(logging.Filter):
    def __init__(self, log_level_config, name=''):
        super().__init__(name)
        self._log_filter = LogFilter(log_level_config, default_level=DEFAULT_LOG_LEVEL)

    def filter(self, record):
        return self._log_filter.should_log(record.name, record.levelname)


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
    return {
        'debug-info': {
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': f'raiden-debug.log',
            'level': 'DEBUG',
            'formatter': 'debug',
            'maxBytes': MAX_LOG_FILE_SIZE,
            'backupCount': 3,
            'filters': ['log_level_debug_filter'],
        },
    }


def redactor(blacklist: Dict[Pattern, str]) -> Callable[[str], str]:
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

    @wraps(TracebackException._orig_format)
    def tracebackexception_format(self, *, chain=True):
        for line in prev_fmt(self, chain=chain):
            yield redact(line)

    TracebackException.format = tracebackexception_format


def configure_logging(
        logger_level_config: Dict[str, str] = None,
        colorize: bool = True,
        log_json: bool = False,
        log_file: str = None,
        disable_debug_logfile: bool = False,
):
    structlog.reset_defaults()

    logger_level_config = logger_level_config or dict()
    logger_level_config.setdefault('filelock', 'ERROR')
    logger_level_config.setdefault('', DEFAULT_LOG_LEVEL)

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
    if disable_debug_logfile:
        combined_log_handlers = log_handler
    else:
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

    # set logging level of the root logger to DEBUG, to be able to intercept
    # all messages, which are then be filtered by the `RaidenFilter`
    structlog.get_logger('').setLevel(logger_level_config.get('', DEFAULT_LOG_LEVEL))
    structlog.get_logger('raiden').setLevel('DEBUG')

    # rollover RotatingFileHandler on startup, to split logs also per-session
    root = logging.getLogger()
    for handler in root.handlers:
        if isinstance(handler, logging.handlers.RotatingFileHandler):
            handler.flush()
            if os.stat(handler.baseFilename).st_size > 0:
                handler.doRollover()

    # fix logging of py-evm (it uses a custom Trace logger from logging library)
    # if py-evm is not used this will throw, hence the try-catch block
    # for some reason it didn't work to put this into conftest.py
    try:
        from eth.tools.logging import setup_trace_logging
        setup_trace_logging()
    except ImportError:
        pass
