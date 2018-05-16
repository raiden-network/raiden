import logging.config
import structlog


def get_log_handler(formatter, log_file, level):
    if log_file:
        return {
            'file': {
                'level': level,
                'class': 'logging.handlers.WatchedFileHandler',
                'filename': log_file,
                'formatter': formatter,
            },
        }
    else:
        return {
            'default': {
                'level': level,
                'class': 'logging.StreamHandler',
                'formatter': formatter,
            }
        }


def configure_logging(
    level='WARN',
    colorize=True,
    log_json=None,
    log_file=None
):
    timestamper = structlog.processors.TimeStamper(fmt="%Y-%m-%d %H:%M:%S")
    pre_chain = [structlog.stdlib.add_log_level, timestamper]
    formatter = 'colorized' if colorize and log_file is '' else 'plain'
    if log_json:
        formatter = 'json'
    log_handler = get_log_handler(formatter, log_file, level)
    logging.config.dictConfig(
        {
            'version': 1,
            'formatters': {
                'plain': {
                    '()': structlog.stdlib.ProcessorFormatter,
                    'processor': structlog.dev.ConsoleRenderer(colors=False),
                    'foreign_pre_chain': pre_chain,
                },
                'json': {
                    '()': structlog.stdlib.ProcessorFormatter,
                    'processor': structlog.processors.JSONRenderer(),
                    'foreign_pre_chain': pre_chain,
                },
                'colorized': {
                    '()': structlog.stdlib.ProcessorFormatter,
                    'processor': structlog.dev.ConsoleRenderer(colors=True),
                    'foreign_pre_chain': pre_chain,
                },
            },
            'handlers': log_handler,
            'loggers': {
                '': {
                    'handlers': list(log_handler.keys()),
                    'level': level,
                    'propagate': True,
                },
            }
        }
    )
    structlog.configure(
        processors=[
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            timestamper,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory()
    )
