import click.testing
import pytest
from project_seaweed import extract_payload
from pytest_mock import MockFixture
from unittest.mock import Mock


@pytest.fixture
def runner():
    return click.testing.CliRunner()


@pytest.fixture
def mock_poc_url(mocker: MockFixture) -> Mock:
    mock = mocker.patch("requests.get")
    mock.return_value.text = "<pre><code>test PoC data</code></pre>"
    mock.return_value.status_code = 200
    return mock


@pytest.fixture
def mock_no_poc_url(mocker: MockFixture) -> Mock:
    mock = mocker.patch("requests.get")
    mock.return_value.text = "<html>no PoC data</html>"
    mock.return_value.status_code = 200
    return mock


def test_no_args(runner):
    result = runner.invoke(extract_payload.main)
    assert result.exit_code == 2


def test_wrong_url(runner):
    result = runner.invoke(extract_payload.main, ["--url", "notavalidurl"])
    assert result.exit_code == 1


def test_extraction(runner, mock_poc_url):
    result = runner.invoke(extract_payload.main, ["--url", "validurl.com"])
    assert result.exit_code == 0
    assert mock_poc_url.called
    assert "test PoC data" in result.output


def test_no_poc(runner, mock_no_poc_url):
    result = runner.invoke(extract_payload.main, ["--url", "validurl.com"])
    assert result.exit_code == 0
    assert mock_no_poc_url.called
    assert "Unable to find payload in the given URL" in result.output
