"""Package wide test fixatures"""

from unittest.mock import Mock
import pytest
from tempfile import mkdtemp

from pytest_mock import MockFixture


@pytest.fixture
def temp_dir() -> str:
    """Creates a temporary directory

    Returns:
        str: name of the temporary directory
    """
    return mkdtemp()


@pytest.fixture
def mock_head_request(mocker: MockFixture) -> Mock:
    """Fixature to patch requests.head function

    Args:
        mocker: patches 'requests.head' code.

    Returns:
        Mock: a mock object which behaves in the same way as the patched code (requests.head response).
    """
    mock = mocker.patch("requests.head")
    mock.return_value.status_code = 200
    return mock


@pytest.fixture
def mock_unreachable_url(mocker: MockFixture) -> Mock:
    """
    Fixature to simulate an unreachable webpage
    """
    mock = mocker.patch("requests.head")
    mock.return_value.status_code = 403
    return mock
