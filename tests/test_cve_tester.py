"""
tests for the cve_tester class
"""

import pytest
from project_seaweed.cve_tester import Cve_tester
import docker


@pytest.fixture(scope="function")
def cve_object() -> Cve_tester:
    """Create Cve_Tester object with cve IDs

    specifies cve(s) to test. Also tests for invalid/ non existant cves

    Returns:
        Cve_tester: Cve_tester object with cves
    """
    return Cve_tester(
        cve_id=["CVE-2020-35729", "CVE-2022-0595", "cve-2077-1234", "c-not-valid-ve"]
    )


@pytest.fixture(scope="function")
def no_cve_object() -> Cve_tester:
    """Create Cve_Tester object without cve IDs

    Cve_tester object goes out of reference when the calling functions ends. Triggers docker cleanup activities.

    Returns:
        Cve_tester: Cve_tester object without any parameters
    """
    return Cve_tester()


@pytest.fixture
def docker_client() -> docker.DockerClient:
    """Returns a docker client for tests involving containers"""
    return docker.from_env()


def test_crs(no_cve_object: pytest.fixture, docker_client: pytest.fixture) -> None:
    """Test if web server and CRS containers are created successfully"""
    test_obj = no_cve_object
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


def test_get_cves(cve_object: pytest.fixture, no_cve_object: pytest.fixture) -> None:
    """Test parameters for nuclei client are created correctly"""
    cve_test_obj = cve_object
    no_cve_test_obj = no_cve_object
    cve_output = cve_test_obj.get_cves()
    no_cve_output = no_cve_test_obj.get_cves()
    assert cve_test_obj.cve_id[0] in cve_output
    assert cve_test_obj.cve_id[1] in cve_output
    assert no_cve_output == "-t cves -pt http"
