"""Tests for report analyzer"""

import pytest
from project_seaweed.report_analyzer import fetch_latest_test,analyze
from pytest_mock import MockFixture
from unittest.mock import Mock

@pytest.fixture
def mock_github_url(mocker: MockFixture) -> Mock:
    """Fixature to simulate a valid webpage url.

    Args:
        mocker: patches 'requests.get' code.

    Returns:
        Mock: a mock object which behaves in the same way as the patched code (requests.get response).
    """
    mock = mocker.patch("requests.get")
    mock.return_value.text = "2022/Aug/21"
    mock.return_value.status_code = 200
    return mock


def test_fetch_latest_scan(mock_github_url: Mock) -> None:
    dir=fetch_latest_test()
    assert dir == "2022/Aug/21"