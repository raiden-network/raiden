#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests for `pathfinder` package."""

from click.testing import CliRunner

from pathfinder import cli


def test_cli_help():
    """Test the CLI."""
    runner = CliRunner()
    help_result = runner.invoke(cli.main, ['--help'])
    assert help_result.exit_code == 0
    assert 'Show this message and exit.' in help_result.output


def test_cli_matrix_required():
    """Test the CLI."""
    runner = CliRunner()
    result = runner.invoke(cli.main)

    assert result.exit_code == 2
    assert 'Missing option "--matrix-username".' in result.output


def test_cli_matrix_required2():
    """Test the CLI."""
    runner = CliRunner()
    result = runner.invoke(cli.main, [
        '--matrix-username', 'xxx',
    ])

    assert result.exit_code == 2
    assert 'Missing option "--matrix-password".' in result.output
