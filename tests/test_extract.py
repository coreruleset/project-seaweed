from unittest import result
import click.testing
import pytest
from project_seaweed import extract_payload

@pytest.fixture
def runner():
    return click.testing.CliRunner()

def test_no_args(runner):
    result=runner.invoke(extract_payload.main)
    assert result.exit_code==2

def test_wrong_url(runner):
    result=runner.invoke(extract_payload.main,["--url","notavalidurl"])
    assert result.exit_code==0
    assert result.output=="URL not reachable!\n"

def test_extraction(runner):
    result=runner.invoke(extract_payload.main,["--url","https://huntr.dev/bounties/df46e285-1b7f-403c-8f6c-8819e42deb80/"])
    assert result.exit_code==0

def test_no_poc(runner):
    pass