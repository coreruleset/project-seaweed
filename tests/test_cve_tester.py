"""
tests for the cve_tester class
"""

import pytest
from project_seaweed.cve_tester import Cve_tester
import docker


@pytest.fixture(scope='function')
def cve_object():
    return Cve_tester(cve_id=["CVE-2020-35729","CVE-2022-0595","cve-2077-1234"])

@pytest.fixture(scope='function')
def no_cve_object():
    return Cve_tester()

@pytest.fixture
def docker_client():
    return docker.from_env()

def test_crs(no_cve_object:pytest.fixture,docker_client:pytest.fixture)->None:
    test_obj=no_cve_object
    test_obj.create_crs()
    assert len(docker_client.containers.list(filters={"status":"running","name":test_obj.web_server_name})) is not 0
    assert len(docker_client.containers.list(filters={"status":"running","name":test_obj.waf_name})) is not 0

def test_get_cves(cve_object:pytest.fixture,no_cve_object:pytest.fixture):
    cve_test_obj=cve_object
    no_cve_test_obj=no_cve_object
    cve_output=cve_test_obj.get_cves()
    no_cve_output=no_cve_test_obj.get_cves()
    assert cve_test_obj.cve_id[0] in cve_output
    assert cve_test_obj.cve_id[1] in cve_output
    assert no_cve_output == "-t cves -pt http"
