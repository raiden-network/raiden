import sys
import time
import logging
import logging.config
import re
from traceback import TracebackException
from functools import wraps
from typing import Dict, Callable, Pattern, Tuple, List

import structlog

DEFAULT_LOG_LEVEL = 'INFO'
MAX_LOG_FILE_SIZE = 5 * 1024 * 1024


def match_list(module_rule: Tuple[List[str], str], logger_module: str) -> Tuple[int, str]:
    logger_modules_split = logger_module.split('.')

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


def get_log_level(
    module_rules: List[Tuple[List[str], str]],
    logger_module: str,
    default_log_level: str = DEFAULT_LOG_LEVEL,
) -> str:
    best_match_length = 0
    best_match_level = default_log_level

    for module in module_rules:
        match_length, level = match_list(module, logger_module)

        if match_length > best_match_length:
            best_match_length = match_length
            best_match_level = level

    return best_match_level


class RaidenFilter(logging.Filter):
    def __init__(self, log_level_config, name=''):
        super().__init__(name)
        self._log_rules = [
            (logger.split('.'), level)
            for logger, level in log_level_config.items()
        ]

    def filter(self, record):
        event_dict = record.msg
        # this check is needed as the flask logs somehow don't get processed by structlog
        if isinstance(event_dict, dict):
            log_level_per_rule = get_log_level(self._log_rules, event_dict.get('logger', ''))
            log_level_event = event_dict.get('level', DEFAULT_LOG_LEVEL).upper()

            log_level_per_rule_numeric = getattr(logging, log_level_per_rule.upper(), 10)
            log_level_event_numeric = getattr(logging, log_level_event.upper(), 10)

            # Propgate the event when the log level is lower than the threshold
            if log_level_event_numeric < log_level_per_rule_numeric:
                return False

        return True


def _get_log_handler(formatter: str, log_file: str, log_level: str) -> Dict:
    if log_file:
        return {
            'file': {
                'class': 'logging.handlers.WatchedFileHandler',
                'filename': log_file,
                'level': log_level,
                'formatter': formatter,
                'filters': ['log_level_config_filter'],
            },
        }
    else:
        return {
            'default': {
                'class': 'logging.StreamHandler',
                'level': log_level,
                'formatter': formatter,
                'filters': ['log_level_config_filter'],
            },
        }


def _get_log_file_handler() -> Dict:
    time_suffix = time.strftime("%Y-%m-%d_%H-%M-%S")
    return {
        'debug-info': {
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': f'raiden-debug-{time_suffix}.log',
            'formatter': 'debug',
            'level': 'DEBUG',
            'maxBytes': MAX_LOG_FILE_SIZE,
            'backupCount': 1,
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

    redact = redactor({
        re.compile(r'\b(access_?token=)([a-z0-9_-]+)', re.I): r'\1<redacted>',
    })
    wrap_tracebackexception_format(redact)

    log_handler = _get_log_handler(
        formatter,
        log_file,
        logger_level_config.get('', 'DEBUG'),
    )
    debug_log_file_handler = _get_log_file_handler()

    combined_log_handlers = {**log_handler, **debug_log_file_handler}

    logging.config.dictConfig(
        {
            'version': 1,
            'disable_existing_loggers': False,
            'filters': {
                'log_level_config_filter': {
                    '()': RaidenFilter,
                    'log_level_config': logger_level_config,
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
                    'processor': structlog.dev.ConsoleRenderer(colors=False),
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

    # set raiden logging level to DEBUG, to be able to intercept all messages
    structlog.get_logger('').setLevel(logger_level_config.get('', DEFAULT_LOG_LEVEL))
    structlog.get_logger('raiden').setLevel('DEBUG')
