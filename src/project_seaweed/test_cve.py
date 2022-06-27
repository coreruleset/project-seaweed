import sys
import click
import docker
import tempfile
import os
import traceback

class cve_tester:
    def __init__(self, cve_id: list = [], waf_url: str = "crs") -> None:
        if waf_url == "crs":
            self.waf_image = "owasp/modsecurity-crs:apache"
            self.web_server_image = "httpd"
            self.waf_name = "crs-waf"
            self.web_server_name = "httpd-server"
            self.waf_url = f"http://{self.waf_name}"
            self.waf_env = ["PARANOIA=4", f"BACKEND=http://{self.web_server_name}"]
            self.network_name = "seaweed-network"
        else:
            self.waf_url = waf_url
        self.cve_id = cve_id
        self.nuclei_image = "projectdiscovery/nuclei:latest"
        self.client = docker.client.from_env()
        self.temp_dir = tempfile.TemporaryDirectory().name

    def printer(self, msg: str, add: bool = True) -> None:
        if add:
            click.secho(f"[+] {msg}", fg="green")
        else:
            click.secho(f"[-] {msg}", fg="red")

    def create_crs(self) -> None:
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
        if self.cve_id != [""]:
            path = "/root/nuclei-templates/cves/{}/{}.yaml"
            cves = []
            for cve in self.cve_id:
                cve = cve.upper()
                year = cve.split("-")[1]
                cves.append(path.format(year, cve))
            return f"-t {','.join(cves)}"
        else:
            return "-t cves -pt http"

    def create_nuclei(self) -> None:
        self.printer("Creating nuclei container...")
        self.client.containers.run(
            self.nuclei_image,
            remove=True,
            detach=False,
            network=self.network_name or "",
            volumes={self.temp_dir: {"bind": self.temp_dir, "mode": "rw"}},
            entrypoint=f"nuclei -u {self.waf_url} {self.get_cves()} -srd {self.temp_dir}",
        )

    def change_permission(self) -> None:
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
        try:
            self.printer(f"Results stored in {self.temp_dir}")
            if hasattr(self, "waf_name"):
                self.create_crs()
            self.create_nuclei()
            self.change_permission()
        except Exception:
            print(traceback.format_exc())
            sys.exit(1)
        print([x for x in os.walk(self.temp_dir)])

    def __del__(self) -> None:
        self.printer("Cleaning up...", add=False)
        try:
            self.web_server_obj.stop()
        except AttributeError as e:
            pass
        try:
            self.waf_obj.stop()
        except AttributeError as e:
            pass
        try:
            self.network.remove()
        except AttributeError as e:
            pass
