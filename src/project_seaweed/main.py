import click
from .extract_payload import extract
from . import __version__
from .test_cve import cve_tester
import logging


@click.group()
@click.version_option(version=__version__)
@click.option(
    "-l",
    "--level",
    type=click.Choice(["debug", "info"], case_sensitive=False),
    help="Choose output mode",
    default="warning",
    show_default=True,
)
def main(level) -> None:
    logging.basicConfig(level=level.upper())


@click.option(
    "--cve_id",
    required=False,
    help="CVE IDs (CVE-2022-1211, CVE-2022-1609 ...)",
    default="",
)
@click.option(
    "--waf_url",
    required=False,
    help="URL for alternate WAF test (https://cloudflaredomain.com)",
    show_default=True,
    default="crs",
)
@click.command()
def tester(cve_id, waf_url) -> None:
    test = cve_tester(cve_id=cve_id.split(","), waf_url=waf_url)
    test.generate_raw()


@click.command()
@click.option("-u", "--url", required=True, help="URL where the PoC is hosted")
def extract_payload(url: str) -> None:
    extract(url=url)


main.add_command(tester)
main.add_command(extract_payload)
