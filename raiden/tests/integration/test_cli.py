from click.testing import CliRunner
from raiden.ui.cli import run


def test_cli_smoketest():
    runner = CliRunner()
    result = runner.invoke(run, ["smoketest"])
    assert result.exit_code == 0
    assert "[5/5] smoketest successful" in result.output
