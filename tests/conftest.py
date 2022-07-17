"""Package wide test fixatures"""

from click.testing import CliRunner
import pytest
from tempfile import mkdtemp


@pytest.fixture
def runner() -> CliRunner:
    """
    Creates a runner to perform tests via project's CLI.

    Returns:
        CliRunner: object
    """
    return CliRunner()


@pytest.fixture
def temp_dir() -> str:
    """Creates a temporary directory

    Returns:
        str: name of the temporary directory
    """
    return mkdtemp()
