"""helper functions for the program"""
import sys
import requests
import logging
import yaml
import click

def is_reachable(url: str) -> bool:
    """Returns True only if URL is alive and responds with 200 OK"""
    try:
        response = requests.head()
        if response.status_code == 200:
            return True
        else:
            return False
    except BaseException:
        sys.exit("URL is not reachable. Exiting program...")

def parse_template(cve:str) -> dict:
    year=cve.split("-")[1]
    file_path=f"nuclei-templates/cves/{year}/{cve}.yaml"
    with open(file_path,"r") as f:
        data=yaml.load(f,Loader=yaml.SafeLoader)['info']
    return {"name":data['name'],"severity":data['name'],"cvss-score":data['cvss-score'],"cwe-id":data['cwe-id'],"tags":data['tags']}

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