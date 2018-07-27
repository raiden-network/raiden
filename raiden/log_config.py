import logging.config
import structlog
import re
from traceback import TracebackException
from functools import wraps
from typing import Dict, Callable, Pattern


DEFAULT_LOG_LEVEL = 'INFO'


def _get_log_handler(formatter, log_file):
    if log_file:
        return {
            'file': {
                'class': 'logging.handlers.WatchedFileHandler',
                'filename': log_file,
                'formatter': formatter,
            },
        }
    else:
        return {
            'default': {
                'class': 'logging.StreamHandler',
                'formatter': formatter,
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


def wrap_tracebackexception_format(redact: Callable[[str], str]):
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
    if logger_level_config is None:
        logger_level_config = {'': DEFAULT_LOG_LEVEL}
    timestamper = structlog.processors.TimeStamper(fmt="%Y-%m-%d %H:%M:%S")
    processors = [
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        timestamper,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    formatter = 'colorized' if colorize and not log_file else 'plain'
    if log_json:
        formatter = 'json'
    log_handler = _get_log_handler(formatter, log_file)

    redact = redactor({
        re.compile(r'\b(access_?token=)([a-z0-9_-]+)', re.I): r'\1<redacted>',
    })
    wrap_tracebackexception_format(redact)

    logging.config.dictConfig(
        {
            'version': 1,
            'disable_existing_loggers': False,
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
            },
            'handlers': log_handler,
            'loggers': {
                '': {
                    'handlers': list(log_handler.keys()),
                    'level': logger_level_config.get('', DEFAULT_LOG_LEVEL),
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
    # set log levels for existing `logging` loggers
    for logger_name, level_name in logger_level_config.items():
        structlog.get_logger(logger_name).setLevel(level_name)
