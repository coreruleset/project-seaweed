"""
tests for the cve_tester class
"""

import pytest
from project_seaweed.cve_tester import Cve_tester
import docker



def test_crs(docker_client: pytest.fixture) -> None:
    """Test if web server and CRS containers are created successfully"""
    test_obj = Cve_tester()
    docker_client=docker.from_env()
    test_obj.create_crs()
    assert (
        len(
            docker_client.containers.list(
                filters={"status": "running", "name": test_obj.web_server_name}
            )
        )
        != 0
    )
    assert (
        len(
            docker_client.containers.list(
                filters={"status": "running", "name": test_obj.waf_name}
            )
        )
        != 0
    )


def test_get_cves() -> None:
    """Test parameters for nuclei client are created correctly"""
    no_cve_object = Cve_tester()
    no_cve_test_obj = no_cve_object
    assert no_cve_test_obj.get_cves() == ["-templates", "cves", "-type", "http"]
    cves=["CVE-2020-35729", "CVE-2022-0595", "cve-2077-1234", "c-not-valid-ve"]
    no_cve_object.cve_id=cves
    cve_output = no_cve_object.get_cves()
    assert cves[0] in cve_output[1]
    assert cves[1] in cve_output[1]
    
