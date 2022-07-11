"""
tests for the cve_tester class
"""

from click.testing import CliRunner
import pytest
from project_seaweed.main import tester
from pytest_mock import MockFixture
from unittest.mock import Mock


def test_no_args(runner: CliRunner) -> None:
    result=runner.invoke(tester,)
