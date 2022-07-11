"""Launch Nuclei exploits against WAFs"""

import sys
import click
import docker
import tempfile
import traceback
import re
import os
import logging
import requests


class Cve_tester:
    """Tester class

    Sets up apache server, modsecurity Waf running rules from Core rule set, nuclei container
    and stores attack requests and waf responses inside a temporary directory.

    Args:
        cve_id: list of cve(s) to test. Tests all available cve(s) by default.
        waf_url: define another url to test. Tests locally setup modsec-crs waf by default.
    Attributes:
        waf_image: defines the owasp crs image to use as a reverse proxy
        web_server_image: defines the image to use for web server behind the reverse proxy
        waf_name: hostname & domain name of the thus setup waf, usefull for providing a target
        url for nuclei.
        web_server_name: hostname & domain name for apache server, used to set the "BACKEND" for waf reverse proxy.
        waf_url: launch exploits with this url as the target
        waf_env: Environment variables to confgure crs waf.
        network_name: name for docker network
        cve_id: list of cve(s) to test. By default runs all cves
        client: docker client to manage docker resources
        temp_dir: name of the temporary directory where results from nuclei are stored
    """

    def __init__(self, cve_id: list, directory: str, waf_url: str = "crs") -> None:
        """
        Initializes attirbutes conditionally.
        If the user provides a waf url, modsec-crs setup is not created. Creates all resources otherwise.
        The availability of waf_url is tested by making a HEAD request.

        Args:
            cve_id: list of cves to test. Tests all by default
            waf_url: define a waf url to test. Uses modsec-crs by default.
            directory: directory to store program output
        """
        if waf_url == "crs":
            logging.info("Initializing modsec-crs setup")
            self.waf_image = "owasp/modsecurity-crs:apache"
            self.web_server_image = "httpd"
            self.waf_name = "crs-waf"
            self.web_server_name = "httpd-server"
            self.waf_url = f"http://{self.waf_name}"
            self.waf_env = ["PARANOIA=4", f"BACKEND=http://{self.web_server_name}"]
            self.network_name = "seaweed-network"
        else:
            try:
                requests.head(waf_url)
            except BaseException:
                sys.exit(f"{waf_url} not reachable! exiting program...")
            logging.info(f"using {waf_url} as target")
            self.waf_url = waf_url
        if directory == "temp":
            self.temp_dir = tempfile.TemporaryDirectory().name
            logging.info(f"Storing results in {self.temp_dir}")
        else:
            if os.path.isdir(directory):
                self.temp_dir = os.path.abspath(directory)
            else:
                sys.exit("Specified directory does not exist. Exiting...")
        self.cve_id = cve_id
        self.nuclei_image = "projectdiscovery/nuclei:latest"
        self.client = docker.client.from_env()

    def printer(self, msg: str, add: bool = True) -> None:
        """
        Display pretty cli messages

        Args:
            msg: message to print
            add: decide the colour of message based on this value
        """
        if add:
            click.secho(f"[+] {msg}", fg="green")
        else:
            click.secho(f"[-] {msg}", fg="red")

    def create_crs(self) -> None:
        """
        Create apache and modsec-crs containers. Attach them to docker network.
        """
        self.printer("Creating docker network...")
        self.network = self.client.networks.create(self.network_name, driver="bridge")
        self.printer("Creating apache server container...")
        self.web_server_obj = self.client.containers.run(
            self.web_server_image,
            name=self.web_server_name,
            network=self.network_name,
            detach=True,
            remove=True,
            hostname=self.web_server_name,
        )
        self.printer("Creating crs-modsec container...")
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
            if self.cve_id=["CVE-2022-1234","CVE-2021-4567"]
            '-t /root/nuclei-templates/cves/2022/CVE-2022-1234.yaml,/root/nuclei-templates/cves/2021/CVE-2021-4567.yaml'

            if self.cve_id=[""]
            '-t cves -pt http'
        """

        if self.cve_id != [""]:
            path = "/root/nuclei-templates/cves/{}/{}.yaml"
            cves = []
            for cve in self.cve_id:
                cve = cve.upper()
                if re.match(r"CVE-\d{4}-\d{1,10}", cve):
                    year = cve.split("-")[1]
                    cves.append(path.format(year, cve))
                else:
                    logging.info(
                        f"{cve} does not match pattern 'CVE-\\d{{4}}-\\d{{1,10}}'. Skippping..."
                    )
                    continue
            return f"-t {','.join(cves)}"
        else:
            logging.info("Testing all available CVEs...")
            return "-t cves -pt http"

    def create_nuclei(self) -> None:
        """
        Creates a docker container to run nuclei against waf using output from get_cves(). Saves nuclei output in temp_dir.
        """
        self.printer("Creating nuclei container...")
        self.client.containers.run(
            self.nuclei_image,
            remove=True,
            detach=False,
            network=self.network_name or "",
            volumes={self.temp_dir: {"bind": self.temp_dir, "mode": "rw"}},
            entrypoint=f"nuclei -u {self.waf_url} {self.get_cves()} -srd {self.temp_dir}",  # nuclei -u http://crs-waf -t cves -pt http -srd /tmp/tmp_1234
        )

    def change_permission(self) -> None:
        """
        Launches an alpine container to change the permissions on the temp_dir directory.
        Previous nuclei container changed the permissions (root only) of temp_dir when it wrote it's output.
        """
        self.printer("Adding permissions to output folder...")
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

    def generate_raw(self) -> None:
        """
        Temporary function for Proof of concept.
        """
        try:
            self.printer(f"Results stored in {self.temp_dir}")
            if hasattr(self, "waf_name"):
                self.create_crs()
            self.create_nuclei()
            self.change_permission()
        except Exception:
            print(traceback.format_exc())
            sys.exit(1)
        # print([x for x in os.walk(self.temp_dir)])
        return self.temp_dir

    def __del__(self) -> None:
        """
        Destructor responsible for cleanup after objects go out of reference.
        Stops the apache and crs containers, which have auto remove enabled. Deletes the docker network.
        """
        self.printer("Cleaning up...", add=False)
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