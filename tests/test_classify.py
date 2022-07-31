"""tests for False negative classifier"""

import json
import pytest
from project_seaweed.classify import Classifier
import os


def response_writer(status: int) -> str:
    """helper function to return response code text strings

    Args:
        status: HTTP response code

    Returns:
        str: HTTP response for the specified status code
    """
    if status == 200:
        return "HTTP/1.1 200 OK\n"
    elif status == 403:
        return "HTTP/1.1 403 Forbidden\n"


@pytest.fixture
def mock_nuclei_results(temp_dir: pytest.fixture) -> str:
    """Simulate nuclei request/response output"""
    dir = temp_dir
    http_dir = dir + "/http"
    os.mkdir(http_dir)

    partial_block_file = f"{http_dir}/CVE_2022_0437.txt"
    full_block_file = f"{http_dir}/CVE_2016_1000131.txt"
    no_block_file = f"{http_dir}/CVE_2020_13937.txt"

    with open(partial_block_file, "w") as f:
        f.write("[CVE-2022-0437]\n")
        f.write(response_writer(403))
        f.write(response_writer(200))

    with open(full_block_file, "w") as f:
        f.write("[CVE-2016-1000131]\n")
        f.write(response_writer(403))

    with open(no_block_file, "w") as f:
        f.write("[CVE-2020-13937]\n")
        f.write(response_writer(200))

    return dir


def test_find_block_type(mock_nuclei_results: pytest.fixture) -> None:
    """Test classifer accuracy"""
    test_obj = Classifier(
        dir=mock_nuclei_results, format="json", out_file="report.json", full_report=True
    )
    status = test_obj.find_block_type("HTTP/1.1 200 OK\nHTTP/1.1 200 OK\n")
    assert status == "Not Blocked"
    status = test_obj.find_block_type(
        "HTTP/1.1 403 Forbidden\nHTTP/1.1 403 Forbidden\n"
    )
    assert status == "Blocked"
    status = test_obj.find_block_type("HTTP/1.1 200 OK\nHTTP/1.1 403 Forbidden\n")
    assert status == "Partial block (50.0%)"


def test_reader(mock_nuclei_results: pytest.fixture) -> None:
    """test generated report without --full-report flag"""
    dir = mock_nuclei_results
    file = f"{dir}/report.json"
    test_obj = Classifier(dir=dir, format="json", out_file=file, full_report=False)
    test_obj.reader()
    assert os.path.exists(file)
    with open(file, "r") as f:
        data = json.load(f)
    assert len(data) == 2
    for i in data:
        assert i["blocked"] != "Blocked"


def test_reader_full(mock_nuclei_results: pytest.fixture) -> None:
    """test generated report with --full-report flag"""
    dir = mock_nuclei_results
    file = f"{dir}/report.json"
    test_obj = Classifier(dir=dir, format="json", out_file=file, full_report=True)
    test_obj.reader()
    assert os.path.exists(file)
    with open(file, "r") as f:
        data = json.load(f)
    assert len(data) == 3
