"""Integration tests for CLI"""

import pytest
from click.testing import CliRunner
from project_seaweed.main import tester
from project_seaweed.main import main

@pytest.fixture
def runner() -> CliRunner:
    """
    Creates a runner to perform tests via project's CLI.

    Returns:
        CliRunner: object
    """
    return CliRunner()

def test_no_args(runner:CliRunner) -> None:
    """Test the CLI without any args"""
    result=runner.invoke(main)
    assert result.exit_code == 0
    assert "Usage" in result.output 

def tester_help_test(runner:CliRunner) -> None:
    """Test cve tester function help"""
    result=runner.invoke(tester,args=["--help"])
    assert result.exit_code == 0
    assert "Usage" in result.output

def test_no_args_tester(runner:CliRunner) -> None:
    """Test basic program functionality with basic args"""
    result=runner.invoke(tester,args=["--cve-id","CVE-2020-13937"]) # Specifying a single CVE, All CVEs are tested by default
    assert result.exit_code == 0

