"""Launch Nuclei exploits against WAFs"""

import subprocess
import sys
from typing import List, Optional
import docker
import tempfile
import traceback
import os
import logging
import requests
from project_seaweed.util import is_reachable, printer, cve_payload_gen, update_analysis


class Cve_tester:
    """Tester class

    Sets up apache server, modsecurity Waf running rules from Core rule set, nuclei
    and stores attack requests and waf responses inside a temporary directory.

    Initializes attributes conditionally. If the user provides a waf url, modsec-crs setup is not created. Creates all resources otherwise.
    The availability of waf_url is tested by making a HEAD request.

    Args:
        cve_id: list of cves to test. Tests all by default
        waf_url: define a waf url to test. Uses modsec-crs by default.
        directory: directory to store program output
        tag: Specify attack templates using tags.
    Attributes:
        waf_image: defines the owasp crs image to use as a reverse proxy
        web_server_image: defines the image to use for web server behind the reverse proxy
        waf_name: hostname & domain name of the thus setup waf, usefull for providing a target
        url for nuclei.
        web_server_name: hostname & domain name for apache server, used to set the "BACKEND" for waf reverse proxy.
        waf_url: launch exploits with this url as the target
        waf_env: Environment variables to confgure crs waf.
        network_name: name for docker network
        client: docker client to manage docker resources
        temp_dir: name of the temporary directory where results from nuclei are stored
    """

    def __init__(
        self,
        cve_id: Optional[List[str]] = None,
        directory: Optional[str] = None,
        waf_url: Optional[str] = None,
        tag: Optional[str] = None,
    ) -> None:
        if waf_url is None:
            logging.info("Initializing modsec-crs setup")
            self.waf_image:str = os.environ.get(
                "WAF_IMAGE", default="owasp/modsecurity-crs:apache"
            )
            self.web_server_image:str = os.environ.get(
                "WEB_SERVER_IMAGE", default="httpd:latest"
            )
            self.waf_name:str = os.environ.get("WAF_NAME", default="crs-waf")
            self.web_server_name:str = os.environ.get(
                "WEB_SERVER_NAME", default="httpd-server"
            )
            self.network_name:str = os.environ.get(
                "NETWORK_NAME", default="seaweed-network"
            )
            self.nuclei_threads:str = os.environ.get(
                "NUCLEI_THREADS", default="10"
            )  # set rate-limiting to 10 nuclei requests / second. Defaults to 150 which overloads CRS at paranoia level 4
            self.waf_url:str = "http://localhost:8080"
            self.waf_env:str = ["PARANOIA=4", "BACKEND=http://" + self.web_server_name]

        elif is_reachable(waf_url):
            logging.info(f"using {waf_url} as target")
            self.waf_url:str = waf_url
        else:
            sys.exit("URL is not reachable. Exiting program...")

        self.temp_dir: str = directory or tempfile.mkdtemp()
        self.cve_id: List = cve_id or []
        self.client = docker.APIClient()
        self.tag:List = ["-tags", tag] if tag is not None else []
        logging.debug(self.__dict__)

    def create_crs(self) -> None:
        """
        Create apache and modsec-crs containers. Attach them to docker network.
        """
        printer("Creating docker network...")
        self.client.create_network(self.network_name, driver="bridge")

        printer("Creating apache server container...")
        image_tag:str = self.web_server_image.split(":")[1]  # httpd:1.2,image_tag=1.2
        self.client.pull(
            self.web_server_image, tag=image_tag
        )  # tag parameter takes precedence even if we define a tag in image name
        self.client.create_container(
            image=self.web_server_image,
            name=self.web_server_name,
            detach=True,
            host_config=self.client.create_host_config(auto_remove=True),
            hostname=self.web_server_name,
        )
        self.client.start(container=self.web_server_name)

        printer("Creating crs-modsec container...")
        image_tag:str = self.waf_image.split(":")[1]
        self.client.pull(self.waf_image, tag=image_tag)
        self.client.create_container(
            image=self.waf_image,
            name=self.waf_name,
            hostname=self.waf_name,
            host_config=self.client.create_host_config(
                auto_remove=True, port_bindings={80: 8080}
            ),
            detach=True,
            ports=[80],
            environment=self.waf_env,
        )
        self.client.start(container=self.waf_name)

        # connect both containers to the same network
        self.client.connect_container_to_network(
            container=self.web_server_name, net_id=self.network_name
        )
        self.client.connect_container_to_network(
            container=self.waf_name, net_id=self.network_name
        )

        waf_version = (
            self.client.inspect_image(image=self.waf_image)["RepoTags"]
            if self.waf_image is not None
            else self.waf_url
        )
        web_server_version = (
            self.client.inspect_image(image=self.web_server_image)["RepoTags"]
            if self.web_server_image is not None
            else self.waf_url
        )
        update_analysis(waf_version=waf_version, web_server_version=web_server_version)

    def get_cves(self) -> List:
        """
        creates the cli arguements for launching nuclei.
        Uses regex to check format for supplied CVEs, skips cve otherwise.

        Returns:
            List: CLI parameters specifying CVE(s) to run.

        Example:
        >>> from project_seaweed.cve_tester import Cve_tester
        >>> test_obj=Cve_tester(cve_id=['CVE-2020-35729','CVE-2022-0595'])
        >>> test_obj.get_cves()
        ['-templates' ,'cves/2020/CVE-2020-35729.yaml,cves/2022/CVE-2022-0595.yaml']
        >>> test_obj=Cve_tester()
        >>> test_obj.get_cves()
        ['-templates', 'cves', '-type', 'http']
        """

        if len(self.cve_id) != 0:
            templates:List = cve_payload_gen(self.cve_id)
            if len(templates) == 0:
                sys.exit("No template found for specified CVE(s). Exiting ...")
            nuclei_arg:List = ["-templates", ",".join(templates)]
        else:
            logging.info("Testing all available CVEs...")
            nuclei_arg:List = ["-templates", "cves", "-type", "http"]
        logging.debug("Nuclei templates: ", nuclei_arg)
        return nuclei_arg

    def start_nuclei(self) -> None:
        """
        Updates and runs nuclei against waf using output from get_cves(). Saves nuclei output in temp_dir.
        """
        printer("Fetching latest nuclei templates...")
        subprocess.run(["nuclei", "-ut"])
        printer("Starting nuclei scans...")
        cves:List = self.get_cves()
        logging.info(
            " ".join(
                [
                    "nuclei",
                    "-target",
                    self.waf_url,
                    "-rate-limit",
                    self.nuclei_threads,
                    "-store-resp-dir",
                    self.temp_dir,
                    *cves,
                    *self.tag,
                ]
            )
        )
        subprocess.run(
            [
                "nuclei",
                "-target",
                self.waf_url,
                "-rate-limit",
                self.nuclei_threads,
                "-store-resp-dir",
                self.temp_dir,
                *cves,
                *self.tag,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        # Fetch the installed version of nuclei templates
        response = requests.get(
            "https://github.com/projectdiscovery/nuclei-templates/releases/latest",
            allow_redirects=False,
        )
        latest_version:str = response.headers["location"].split("/")[-1]
        update_analysis(nuclei_templates_version=latest_version)

    def generate_raw(self) -> str:
        """
        Stitch all the functions together and write the output of testing
        """
        try:
            printer(f"Results stored in {self.temp_dir}")
            if hasattr(self, "waf_name"):
                self.create_crs()
            self.start_nuclei()
        except Exception:
            sys.exit(traceback.format_exc())
        return self.temp_dir

    def __del__(self) -> None:
        """
        Destructor responsible for cleanup after objects go out of reference.
        Stops the apache and crs containers, which have auto remove enabled. Deletes the docker network.
        """
        printer("Cleaning up...", add=False)
        try:
            self.client.stop(container=self.web_server_name)
            logging.info("Stopped web server container")
        except AttributeError:
            pass
        try:
            self.client.stop(container=self.waf_name)
            logging.info("Stopped modsec-crs container")
        except AttributeError:
            pass
        try:
            self.client.remove_network(self.network_name)
            logging.info("Removed Docker network")
        except AttributeError:
            pass
