"""helper functions for the program"""

import os
from typing import Dict, List
import requests
import yaml
import click
import requests
from zipfile import ZipFile
from io import BytesIO
from shutil import rmtree

def is_reachable(url: str) -> bool:
    """Check if URL is alive and responds with 200 OK

    Args:
        url: URL to test

    Returns:
        bool: True if url is alive and responds with 200, False otherwise.
    """
    try:
        response = requests.head(url=url)
        if response.status_code == 200:
            status = True
        else:
            status = False
    except BaseException:
        status = False
    return status


def parse_template(cve: str) -> Dict:
    """Parse nuclei yaml templates and return relevent information

    Assumes nuclei repository is present in the path.

    Args:
        cve: CVE id to identify respective nuclei template

    Returns:
        Dict: return CVE name, severity, cvss-score,cwe-id and tags
    """
    year = cve.split("-")[1]
    file_path = f"nuclei-templates/cves/{year}/{cve}.yaml"
    with open(file_path, "r") as f:
        data = yaml.load(f, Loader=yaml.SafeLoader)["info"]
    return {
        "name": data.get("name", "None"),
        "severity": data.get("severity", "None"),
        "cvss-score": data.get("classification").get("cvss-score", "None")
        if data.get("classification") is not None
        else "None",
        "cwe-id": data.get("classification").get("cwe-id", "None")
        if data.get("classification") is not None
        else "None",
        "tags": data.get("tags", "None"),
    }


def printer(msg: str, add: bool = True) -> None:
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


def cve_payload_gen(cves: List) -> List:
    """Generate path for requested cve

    Args:
        cve: cve for which nuclei template needs to be found

    Returns:
        List: list of paths for nuclei tepmlates
    """
    to_return=[]
    for cve in cves:
        try:
            template = f"nuclei-templates/cves/{cve.split('-')[1]}/{cve.upper()}.yaml"
            if os.path.exists(template):
                to_return.append("/root/"+template)
        except IndexError:
            pass
    return to_return

def fetch_nuclei_templates() -> None:
    """Fetches latest nuclei templates"""
    if os.path.exists("nuclei-templates"):
        rmtree("nuclei-templates")
    url="https://github.com/projectdiscovery/nuclei-templates/archive/refs/heads/master.zip"
    resp=requests.get(url=url)
    with ZipFile(BytesIO(resp.content)) as zip:
        zip.extractall()
    os.rename("nuclei-templates-master","nuclei-templates")