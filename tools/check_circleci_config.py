#!/usr/bin/env python3

"""
Utility to ensure correctness of the CircleCI workflow
"""
import sys
from difflib import unified_diff

import click
import yaml
from yaml.parser import ParserError


def _red(string):
    return click.style(string, fg='red')


def _green(string):
    return click.style(string, fg='green')


def _yellow(string):
    return click.style(string, fg='yellow')


def _check_workflows_align(config):
    """
    Ensure that the common shared jobs in the `raiden-default` and `nightly` workflows are
    identical.
    """

    jobs_default = config['workflows']['raiden-default']['jobs']
    jobs_nightly = config['workflows']['nightly']['jobs']

    if jobs_default == jobs_nightly[:len(jobs_default)]:
        return True, []

    job_diff = unified_diff(
        [f"{line}\n" for line in jobs_default],
        [f"{line}\n" for line in jobs_nightly[:len(jobs_default)]],
        'raiden-default',
        'nightly',
    )
    message = [
        _yellow(
            "Mismatch in common items of workflow definitions 'raiden-default' and "
            "'nightly':\n",
        ),
    ]
    for line in job_diff:
        if line.startswith('-'):
            message.append(_red(line))
        elif line.startswith('+'):
            message.append(_green(line))
        else:
            message.append(line)

    return False, ''.join(message)


@click.command()
@click.argument('circle-config-file', type=click.File('rt'), default='.circleci/config.yml')
def main(circle_config_file):
    try:
        config = yaml.safe_load(circle_config_file)
    except ParserError as ex:
        click.secho(f'Invalid yaml file: {ex}', fg='red')
        sys.exit(1)

    result, message = _check_workflows_align(config)
    if result is False:
        click.echo(message)
        sys.exit(1)


if __name__ == "__main__":
    main()
