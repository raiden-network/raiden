# make it possible to run raiden with 'python -m raiden'


def main() -> None:
    import gevent.monkey

    gevent.monkey.patch_all()

    import asyncio  # isort:skip # noqa
    import raiden.network.transport.matrix.rtc.aiogevent as aiogevent  # isort:skip # noqa

    asyncio.set_event_loop_policy(aiogevent.EventLoopPolicy())  # isort:skip # noqa
    gevent.spawn(asyncio.get_event_loop().run_forever)  # isort:skip # noqa

    from raiden.ui.cli import run

    # auto_envvar_prefix on a @click.command will cause all options to be
    # available also through environment variables prefixed with given prefix
    # http://click.pocoo.org/6/options/#values-from-environment-variables
    run(auto_envvar_prefix="RAIDEN")  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    main()
