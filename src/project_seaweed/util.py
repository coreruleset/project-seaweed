"""helper functions for the program"""

import json
import logging
import os
from typing import Dict, List
import requests
import yaml
import click

home_dir = os.path.expanduser("~")


def is_reachable(url: str) -> bool:
    """Check if URL is alive and responds with 200 OK

    Args:
        url: URL to test

    Returns:
        bool: True if url is alive and responds with 200, False otherwise.
    """
    logging.info(f"Testing url availability: {url}")
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
    file_path = f"{home_dir}/nuclei-templates/cves/{year}/{cve}.yaml"
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
        cves: list of cves for which nuclei templates needs to be found

    Returns:
        List: list of paths for nuclei tepmlates
    """
    to_return = []
    for cve in cves:
        try:
            year = cve.split("-")[1]
            template = f"{home_dir}/nuclei-templates/cves/{year}/{cve.upper()}.yaml"
            if os.path.exists(template):
                to_return.append(template)
        except IndexError:
            pass
    return to_return

def update_analysis(**kwargs):
    with open("analysis.yaml","a+") as f:
        data=yaml.load(f, Loader=yaml.SafeLoader) or {}
        data.update(kwargs)
        yaml.dump(data,f)