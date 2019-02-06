import json
import logging
import os
import sys
import traceback
from collections import defaultdict
from datetime import datetime
from os.path import basename
from pathlib import Path

import click
import gevent
import structlog
from eth_utils import to_checksum_address
from urwid import ExitMainLoop
from web3.utils.transactions import TRANSACTION_DEFAULTS

from raiden.accounts import Account
from raiden.log_config import _FIRST_PARTY_PACKAGES, configure_logging
from scenario_player import tasks
from scenario_player.exceptions import ScenarioAssertionError, ScenarioError
from scenario_player.runner import ScenarioRunner
from scenario_player.tasks.base import collect_tasks
from scenario_player.ui import (
    LOGGING_PROCESSORS,
    NonStringifyingProcessorFormatter,
    ScenarioUI,
    UrwidLogRenderer,
    UrwidLogWalker,
)
from scenario_player.utils import (
    ChainConfigType,
    ConcatenableNone,
    DummyStream,
    send_notification_mail,
)

log = structlog.get_logger(__name__)

TRANSACTION_DEFAULTS['gas'] = lambda web3, tx: web3.eth.estimateGas(tx) * 2


@click.group(invoke_without_command=True, context_settings={'max_content_width': 120})
@click.option('--keystore-file', required=True, type=click.Path(exists=True, dir_okay=False))
@click.password_option('--password', envvar='ACCOUNT_PASSWORD', required=True)
@click.option(
    '--chain',
    'chains',
    type=ChainConfigType(),
    multiple=True,
    required=True,
    help='Chain name to eth rpc url mapping, multiple allowed',
)
@click.option(
    '--data-path',
    default=os.path.join(os.path.expanduser('~'), '.raiden', 'scenario-player'),
    type=click.Path(exists=False, dir_okay=True, file_okay=False),
    show_default=True,
)
@click.option('--auth', default='')
@click.option('--mailgun-api-key')
@click.argument('scenario-file', type=click.File(), required=False)
@click.pass_context
def main(
    ctx,
    scenario_file,
    keystore_file,
    password,
    chains,
    data_path,
    auth,
    mailgun_api_key,
):
    gevent.get_hub().exception_stream = DummyStream()

    is_subcommand = ctx.invoked_subcommand is not None
    if not is_subcommand and scenario_file is None:
        ctx.fail('No scenario definition file provided')

    if is_subcommand:
        log_file_name = (
            f'scenario-player-{ctx.invoked_subcommand}_{datetime.now():%Y-%m-%dT%H:%M:%S}.log'
        )
    else:
        scenario_basename = basename(scenario_file.name)
        log_file_name = (
            f'scenario-player_{scenario_basename}_{datetime.now():%Y-%m-%dT%H:%M:%S}.log'
        )
    click.secho(f'Writing log to {log_file_name}', fg='yellow')
    configure_logging(
        {'': 'INFO', 'raiden': 'DEBUG', 'scenario_player': 'DEBUG'},
        debug_log_file_name=log_file_name,
        _first_party_packages=_FIRST_PARTY_PACKAGES | frozenset(['scenario_player']),
    )

    log_buffer = None
    if sys.stdout.isatty() and not is_subcommand:
        log_buffer = UrwidLogWalker([])
        for handler in logging.getLogger('').handlers:
            if isinstance(handler, logging.StreamHandler):
                handler.terminator = ConcatenableNone()
                handler.formatter = NonStringifyingProcessorFormatter(
                    UrwidLogRenderer(),
                    foreign_pre_chain=LOGGING_PROCESSORS,
                )
                handler.stream = log_buffer
                break

    chain_rpc_urls = defaultdict(list)
    for chain_name, chain_rpc_url in chains:
        chain_rpc_urls[chain_name].append(chain_rpc_url)

    with open(keystore_file, 'r') as keystore:
        account = Account(json.load(keystore), password, keystore_file)
        log.info("Using account", account=to_checksum_address(account.address))

    if is_subcommand:
        ctx.obj = dict(
            account=account,
            chain_rpc_urls=chain_rpc_urls,
            data_path=data_path,
        )
        return

    # Collect tasks
    collect_tasks(tasks)

    runner = ScenarioRunner(account, chain_rpc_urls, auth, Path(data_path), scenario_file)
    ui = ScenarioUI(runner, log_buffer, log_file_name)
    ui_greenlet = ui.run()
    success = False
    try:
        try:
            runner.run_scenario()
            success = True
            log.info('Run finished', result='success')
            send_notification_mail(
                runner.notification_email,
                f'Scenario successful {scenario_file.name}',
                'Success',
                mailgun_api_key,
            )
        except ScenarioAssertionError as ex:
            log.error('Run finished', result='assertion errors')
            send_notification_mail(
                runner.notification_email,
                f'Assertion mismatch in {scenario_file.name}',
                str(ex),
                mailgun_api_key,
            )
        except ScenarioError:
            log.exception('Run finished', result='scenario error')
            send_notification_mail(
                runner.notification_email,
                f'Invalid scenario {scenario_file.name}',
                traceback.format_exc(),
                mailgun_api_key,
            )
    except Exception:
        log.exception('Exception while running scenario')
        send_notification_mail(
            runner.notification_email,
            f'Error running scenario {scenario_file.name}',
            traceback.format_exc(),
            mailgun_api_key,
        )
    finally:
        try:
            if sys.stdout.isatty():
                ui.set_success(success)
                log.warning('Press q to exit')
                while not ui_greenlet.dead:
                    gevent.sleep(1)
        finally:
            if runner.is_managed:
                runner.node_controller.stop()
            if not ui_greenlet.dead:
                ui_greenlet.kill(ExitMainLoop)
                ui_greenlet.join()


@main.command(name='reclaim-eth')
@click.option(
    '--min-age', default=72, show_default=True,
    help='Minimum account non-usage age before reclaiming eth. In hours.',
)
@click.pass_obj
def reclaim_eth(obj, min_age):
    from scenario_player.utils import reclaim_eth

    reclaim_eth(min_age_hours=min_age, **obj)


if __name__ == "__main__":
    main()
