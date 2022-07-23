"""Package wide test fixatures"""

import pytest
from tempfile import mkdtemp



@pytest.fixture
def temp_dir() -> str:
    """Creates a temporary directory

    Returns:
        str: name of the temporary directory
    """
    return mkdtemp()
