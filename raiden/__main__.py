# make it possible to run raiden with 'python -m raiden'


def main():
    import gevent.monkey
    gevent.monkey.patch_all()
    from raiden.ui.cli import run
    run(auto_envvar_prefix='RAIDEN')


if __name__ == "__main__":
    main()
