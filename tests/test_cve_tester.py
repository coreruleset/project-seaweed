"""
tests for the cve_tester class
"""

from click.testing import CliRunner
import pytest
from project_seaweed.main import tester
from project_seaweed.cve_tester import Cve_tester
from pytest_mock import MockFixture
from unittest.mock import Mock


"""def test_no_args(runner: CliRunner) -> None:
    result=runner.invoke(tester,)

def test_initialization():
    test_obj=Cve_tester(cve_id=["CVE-2020-35729","CVE-2022-0595"])
"""