"""Package wide test fixatures"""

from click.testing import CliRunner
import pytest


@pytest.fixture
def runner() -> CliRunner:
    """
    Returns a runner to perform tests via project's CLI.
    """
    return CliRunner()
