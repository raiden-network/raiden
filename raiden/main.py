from gevent import monkey
monkey.patch_all()
from raiden.ui.cli import run


if __name__ == '__main__':
    # auto_envvar_prefix on a @click.command will cause all options to be
    # available also through environment variables prefixed with given prefix
    # http://click.pocoo.org/6/options/#values-from-environment-variables
    run(auto_envvar_prefix='RAIDEN')
