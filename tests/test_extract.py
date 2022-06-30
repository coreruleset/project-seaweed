"""
tests for the PoC extraction function
"""

from click.testing import CliRunner
import pytest
from project_seaweed.main import extract_payload
from pytest_mock import MockFixture
from unittest.mock import Mock


@pytest.fixture
def runner() -> CliRunner:
    """
    Returns a runner to perform tests via project's CLI.
    """
    return CliRunner()


@pytest.fixture
def mock_poc_url(mocker: MockFixture) -> Mock:
    """
    Fixature to simulate a valid webpage url.
    Args:
        mocker: patches 'requests.get' code.
    Returns:
        mock: a mock object which behaves in the same way as the patched code (requests.get response).
    """
    mock = mocker.patch("requests.get")
    mock.return_value.text = "<pre><code>test PoC data</code></pre>"
    mock.return_value.status_code = 200
    return mock


@pytest.fixture
def mock_no_poc_url(mocker: MockFixture) -> Mock:
    """
    Fixature to simulate a valid webpage but does not contain any exploit Poc or payload.
    """
    mock = mocker.patch("requests.get")
    mock.return_value.text = "<html>no PoC data</html>"
    mock.return_value.status_code = 200
    return mock


@pytest.fixture
def mock_unreachable_url(mocker: MockFixture) -> Mock:
    """
    Fixature to simulate an unreachable webpage
    """
    mock = mocker.patch("requests.get")
    mock.return_value.status_code = 403
    return mock


def test_no_args(runner: CliRunner) -> None:
    """
    Program exits with code 2 when no cli args are provided
    """
    result = runner.invoke(extract_payload)
    assert result.exit_code == 2


def test_unreachable_url(
    runner: CliRunner, mock_unreachable_url: pytest.fixture
) -> None:
    """
    Program handles the case when provided url is down.
    Args:
        runner: CLIRunner object to simulate cli interaction
        mock_unreachable_url: fixature to return a valid request.get response object
    """
    result = runner.invoke(extract_payload, ["--url", "validurl.com"])
    assert mock_unreachable_url.called
    assert "URL not reachable!" in result.output


def test_wrong_url(runner: CliRunner) -> None:
    """
    Program handles the case when provided url is not a valid one.
    invalid: not being the format a url is supposed to be.
    """
    result = runner.invoke(extract_payload, ["--url", "notavalidurl"])
    assert result.exit_code == 1


def test_extraction(runner: CliRunner, mock_poc_url: pytest.fixture) -> None:
    """
    Programm successfully extracts payload
    """
    result = runner.invoke(extract_payload, ["--url", "validurl.com"])
    assert result.exit_code == 0
    assert mock_poc_url.called
    assert "test PoC data" in result.output


def test_no_poc(runner: CliRunner, mock_no_poc_url: pytest.fixture) -> None:
    """
    Provided url is valid and reachable but does not contain any exploit PoC / code / payload
    """
    result = runner.invoke(extract_payload, ["--url", "validurl.com"])
    assert result.exit_code == 0
    assert mock_no_poc_url.called
    assert "Unable to find payload in the given URL" in result.output
