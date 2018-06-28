import logging.config
import structlog
from typing import Dict


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
    logging.config.dictConfig(
        {
            'version': 1,
            'disable_existing_loggers': False,
            'formatters': {
                'plain': {
                    '()': structlog.stdlib.ProcessorFormatter,
                    'processor': structlog.dev.ConsoleRenderer(colors=False),
                    'foreign_pre_chain': processors,
                },
                'json': {
                    '()': structlog.stdlib.ProcessorFormatter,
                    'processor': structlog.processors.JSONRenderer(),
                    'foreign_pre_chain': processors,
                },
                'colorized': {
                    '()': structlog.stdlib.ProcessorFormatter,
                    'processor': structlog.dev.ConsoleRenderer(colors=True),
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
