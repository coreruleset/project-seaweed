"""Package wide test fixatures"""

from click.testing import CliRunner
import pytest
from tempfile import mkdtemp

@pytest.fixture
def runner() -> CliRunner:
    """
    Returns a runner to perform tests via project's CLI.
    """
    return CliRunner()

@pytest.fixture
def temp_dir():
    return mkdtemp()