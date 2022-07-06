"""Entrypoint program & CLI interface"""

import click
from .extract_payload import extract
from . import __version__
from .cve_tester import cve_tester
import logging


@click.group()
@click.version_option(version=__version__)
@click.option(
    "-l",
    "--level",
    type=click.Choice(["debug", "info", "warning"], case_sensitive=False),
    help="Choose log level",
    default="warning",
    show_default=True,
)
def main(level: str) -> None:
    """
    Entrypoint function for the whole project. Also defines the logging format and level.

    Args:
        level: declares the logging level for the project (info|debug|none)
    """
    logging.basicConfig(
        level=level.upper(), format="%(asctime)s - %(levelname)s - %(message)s"
    )


@click.option(
    "--cve-id",
    "cve_id",
    required=False,
    help="CVE IDs (CVE-2022-1211, CVE-2022-1609 ...)",
    default="",
)
@click.option(
    "--waf-url",
    "waf_url",
    required=False,
    help="URL for alternate WAF test (https://cloudflaredomain.com)",
    show_default=True,
    default="crs",
)
@click.option(
    "--out",
    "directory",
    required=False,
    help="Specify directory to store output",
    default="temp",
)
@click.command()
def tester(cve_id: str, directory: str, waf_url: str) -> None:
    """
    Triggers the cve testing process using the cve_test class object and then calling the generate_raw().
    Args:
        cve_id: comma separated values for cve(s) to test.
        waf_url: specify a waf other than modsec-crs
    """
    test = cve_tester(cve_id=cve_id.split(","), directory=directory, waf_url=waf_url)
    test.generate_raw()


@click.command()
@click.option("-u", "--url", required=True, help="URL where the PoC is hosted")
def extract_payload(url: str) -> None:
    """
    extracts the exploit PoC from the given webpage URL.

    Args:
        url: url of the webpage to parse
    """
    extract(url=url)


main.add_command(tester)
main.add_command(extract_payload)
