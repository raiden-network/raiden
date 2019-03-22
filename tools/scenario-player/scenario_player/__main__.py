from gevent import monkey

monkey.patch_all()


if __name__ == "__main__":
    from .main import main
    main(  # pylint: disable=unexpected-keyword-arg,no-value-for-parameter
        prog_name='python -m scenario_player',
    )
