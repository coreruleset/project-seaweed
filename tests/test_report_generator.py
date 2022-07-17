"""
tests for the report generation
"""

import os
from typing import Generator
import pytest
from project_seaweed.report_generator import cve_details, Report
from collections import OrderedDict


def cve_data(amount: int = 1) -> Generator:
    for i in range(amount):
        yield cve_details(cve=f"CVE-2005-{i}", severity="critical", type="XSS")


def test_cve_datatype() -> None:
    """Checks if a dictionary is created from provided CVE details

    Also checks if dictionary elements appear in the order of insertion
    """
    test_obj = cve_details(cve="CVE-2005-1234", severity="critical", type="SQLi")
    assert isinstance(test_obj.output(), OrderedDict)
    target_list = ["cve", "severity", "type"]
    for i in range(3):
        assert target_list[i] == test_obj.keys()[i]


def test_csv_report(temp_dir: pytest.fixture) -> None:
    out_file = f"{temp_dir}/report.csv"
    report_obj = Report("csv", out_file=out_file)
    for i in cve_data(3):
        report_obj.add_data(i)
    report_obj.gen_file()
    assert os.path.exists(out_file)


def test_json_report(temp_dir: pytest.fixture) -> None:
    out_file = f"{temp_dir}/report.json"
    report_obj = Report("json", out_file=out_file)
    for i in cve_data(3):
        report_obj.add_data(i)
    report_obj.gen_file()
    assert os.path.exists(out_file)
