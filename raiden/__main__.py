# make it possible to run raiden with 'python -m raiden'


def main():
    import gevent.monkey
    gevent.monkey.patch_all()
    from raiden.ui.cli import run
    run()


if __name__ == "__main__":
    main()
