# make it possible to run raiden with 'python -m raiden'


def main() -> None:
    import gevent.monkey

    gevent.monkey.patch_all()

    from raiden.network.transport.matrix.rtc.utils import setup_asyncio_event_loop

    setup_asyncio_event_loop()

    from raiden.ui.cli import run

    # auto_envvar_prefix on a @click.command will cause all options to be
    # available also through environment variables prefixed with given prefix
    # http://click.pocoo.org/6/options/#values-from-environment-variables
    run(auto_envvar_prefix="RAIDEN")  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    main()
