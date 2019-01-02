"""Tests for `pathfinding_service` package."""

from click.testing import CliRunner

from pathfinding_service import cli


def test_cli_help():
    """Test the CLI."""
    runner = CliRunner()
    help_result = runner.invoke(cli.main, ['--help'])
    assert help_result.exit_code == 0
    assert 'Show this message and exit.' in help_result.output
