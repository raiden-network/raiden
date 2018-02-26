#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests for `pathfinder` package."""

import pytest
from click.testing import CliRunner

from pathfinder import cli


def test_command_line_interface():
    """Test the CLI."""
    runner = CliRunner()
    help_result = runner.invoke(cli.main, ['--help'])
    assert help_result.exit_code == 0
    assert 'Show this message and exit.' in help_result.output
