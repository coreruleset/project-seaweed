"""Launch Nuclei exploits against WAFs"""

import sys
from typing import List
import docker
import tempfile
import traceback
import os
import logging
from .util import is_reachable, printer, cve_payload_gen


class Cve_tester:
    """Tester class

    Sets up apache server, modsecurity Waf running rules from Core rule set, nuclei container
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
        cve_id: list = None,
        directory: str = None,
        waf_url: str = None,
        tag: str = None,
    ) -> None:
        if waf_url is None:
            logging.info("Initializing modsec-crs setup")
            self.waf_image = os.environ.get(
                "WAF_IMAGE", default="owasp/modsecurity-crs:apache"
            )
            self.web_server_image = os.environ.get(
                "WEB_SERVER_IMAGE", default="httpd:latest"
            )
            self.waf_name = os.environ.get("WAF_NAME", default="crs-waf")
            self.web_server_name = os.environ.get(
                "WEB_SERVER_NAME", default="httpd-server"
            )
            self.network_name = os.environ.get(
                "NETWORK_NAME", default="seaweed-network"
            )
            self.nuclei_image = os.environ.get(
                "NUCLEI_IMAGE", default="projectdiscovery/nuclei:latest"
            )
            self.nuclei_threads = os.environ.get(
                "NUCLEI_THREADS", default=10
            )  # set rate-limiting to 10 nuclei requests / second. Defaults to 150 which overloads CRS at paranoia level 4
            self.waf_url = "http://" + self.waf_name
            self.waf_env = ["PARANOIA=4", "BACKEND=http://" + self.web_server_name]

        elif is_reachable(waf_url):
            logging.info(f"using {waf_url} as target")
            self.waf_url = waf_url
        else:
            sys.exit("URL is not reachable. Exiting program...")

        self.temp_dir:str = directory or tempfile.mkdtemp()
        self.cve_id:List = cve_id or []
        self.client = docker.client.from_env()
        self.tag = "-tags " + tag if tag is not None else ""

    def create_crs(self) -> None:
        """
        Create apache and modsec-crs containers. Attach them to docker network.
        """
        printer("Creating docker network...")
        self.network = self.client.networks.create(self.network_name, driver="bridge")
        printer("Creating apache server container...")
        image_tag=self.web_server_image.split(':')[1] # httpd:1.2,image_tag=1.2
        self.client.images.pull(self.web_server_image,tag=image_tag) # tag parameter takes precedence even if we define a tag in image name
        self.web_server_obj = self.client.containers.run(
            self.web_server_image,
            name=self.web_server_name,
            network=self.network_name,
            detach=True,
            remove=True,
            hostname=self.web_server_name,
        )
        printer("Creating crs-modsec container...")
        image_tag=self.waf_image.split(':')[1]
        self.client.images.pull(self.waf_image,tag=image_tag)
        self.waf_obj = self.client.containers.run(
            self.waf_image,
            name=self.waf_name,
            hostname=self.waf_name,
            network=self.network_name,
            remove=True,
            detach=True,
            environment=self.waf_env,
        )

    def get_cves(self) -> str:
        """
        creates the cli arguements for launching nuclei.
        Uses regex to check format for supplied CVEs, skips cve otherwise.

        Returns:
            str: CLI parameters specifying CVE(s) to run.

        Example:
        >>> from project_seaweed.cve_tester import Cve_tester
        >>> test_obj=Cve_tester(cve_id='CVE-2020-35729,CVE-2022-0595')
        >>> test_obj.get_cves()
        '-t cves/2020/CVE-2020-35729.yaml,cves/2022/CVE-2022-0595.yaml'
        >>> test_obj=Cve_tester()
        >>> test_obj.get_cves()
        '-t cves -pt http'
        """

        if len(self.cve_id) != 0:
            templates=cve_payload_gen(self.cve_id)
            if len(templates) == 0:
                sys.exit("No template found for specified CVE(s)")
            nuclei_arg = f"-t {','.join(templates)}"
        else:
            logging.info("Testing all available CVEs...")
            nuclei_arg = "-t cves -pt http"
        return nuclei_arg

    def create_nuclei(self) -> None:
        """
        Creates a docker container to run nuclei against waf using output from get_cves(). Saves nuclei output in temp_dir.
        """
        printer("Creating nuclei container...")
        # nuclei -u http://crs-waf -rl 50 -t cves -pt http -srd /tmp/tmp_1234
        entry_cmd = f"nuclei -u {self.waf_url} -rl {self.nuclei_threads} {self.get_cves()} {self.tag} -srd {self.temp_dir}"
        image_tag=self.nuclei_image.split(':')[1]
        self.client.images.pull(self.nuclei_image,tag=image_tag)
        self.nuclei_obj = self.client.containers.run(
            self.nuclei_image,
            remove=True,
            detach=False,
            network=self.network_name or "",
            volumes={self.temp_dir: {"bind": self.temp_dir, "mode": "rw"}},
            entrypoint=entry_cmd,
        )

    def change_permission(self) -> None:
        """
        Launches an alpine container to change the permissions on the temp_dir directory.
        Previous nuclei container changed the permissions (root only) of temp_dir when it wrote it's output.
        """
        printer("Adding permissions to output folder...")
        self.client.containers.run(
            "alpine",
            remove=True,
            detach=True,
            volumes={
                self.temp_dir: {
                    "bind": self.temp_dir,
                    "mode": "rw",
                }
            },
            tty=True,
            command=f"sh -c 'chmod -R 777 {self.temp_dir}'",
        )

    def generate_raw(self) -> str:
        """
        Stich all the functions together and write the output of testing
        """
        try:
            printer(f"Results stored in {self.temp_dir}")
            if hasattr(self, "waf_name"):
                self.create_crs()
            self.create_nuclei()
            self.change_permission()
        except Exception:
            print(traceback.format_exc())
            sys.exit(1)
        return self.temp_dir

    def __del__(self) -> None:
        """
        Destructor responsible for cleanup after objects go out of reference.
        Stops the apache and crs containers, which have auto remove enabled. Deletes the docker network.
        """
        printer("Cleaning up...", add=False)
        try:
            self.nuclei_obj.stop()
        except AttributeError:
            pass
        try:
            self.web_server_obj.stop()
        except AttributeError:
            pass
        try:
            self.waf_obj.stop()
        except AttributeError:
            pass
        try:
            self.network.remove()
        except AttributeError:
            pass
