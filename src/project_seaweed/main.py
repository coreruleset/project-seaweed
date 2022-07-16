"""Entrypoint program & CLI interface"""

import os
from pydoc import cli
from unittest import case
from . import __version__
import click
from .extract_payload import extract
from .classify import Classifier
from .cve_tester import Cve_tester
import logging


@click.group()
@click.version_option(version=__version__)
@click.option(
    "-l",
    "--log-level",
    "level",
    type=click.Choice(["debug", "info", "warning"], case_sensitive=False),
    help="log level",
    default="warning",
    show_default=True,
)
def main(level: str) -> None:
    """Project Seaweed
    \f
    Args:
        level: log level for the program
    """
    logging.basicConfig(
        level=level.upper(), format="%(asctime)s - %(levelname)s - %(message)s"
    )
    logging.info(f"Logging enabled. Level: {level}")


@click.option(
    "--cve-id",
    "cve_id",
    required=False,
    help="CVE IDs (CVE-2022-1211, CVE-2022-1609 ...), Runs all CVEs by default",
    default="",
)
@click.option(
    "--waf-url",
    "waf_url",
    required=False,
    help="URL for alternate WAF test (https://cloudflaredomain.com)",
    show_default=True,
)
@click.option(
    "--out-dir",
    "directory",
    required=False,
    help="Specify directory to store nuclei requests/responses",
)
@click.option(
    "--full-report",
    "full_report",
    default=False,
    help="Includes blocked attack's info in the report (bigger report)",
)
@click.option(
    "--format",
    "format",
    type=click.Choice(["json", "csv"], case_sensitive=True),
    default="json",
    show_default=True,
    help="format for report",
)
@click.option(
    "--out-file", "out_file", required=False, help="location to save the file"
)
@click.command()
def tester(
    cve_id: str, directory: str, waf_url: str, full_report: bool, out_file: str
) -> None:
    """Trigger CVE testing process
    \f
    Triggers the cve testing process using the cve_test class object and then calling the generate_raw().

    Args:
        cve_id: comma separated values for cve(s) to test.
        waf_url: specify a waf other than modsec-crs
        directory: specify directory to store program output
    """
    test = Cve_tester(cve_id=cve_id.split(","), directory=directory, waf_url=waf_url)
    result_directory = test.generate_raw()
    classify = Classifier(result_directory)


"""@click.command()
@click.option("-u", "--url", required=True, help="URL where the PoC is hosted")
def extract_payload(url: str) -> None:
    #Extracts the exploit PoC from the given webpage URL.

    Args:
        url: url of the webpage to parse
    #
    extract(url=url)"""

main.add_command(tester)
# main.add_command(extract_payload)
