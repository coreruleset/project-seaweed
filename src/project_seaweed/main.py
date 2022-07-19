"""Entrypoint program & CLI interface"""

from . import __version__
import click
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
    help="CVE IDs (CVE-2022-1211, CVE-2022-1609 ...), Runs all CVEs by default"
)
@click.option(
    "--waf-url",
    "waf_url",
    required=False,
    help="URL for alternate WAF test (https://cloudflaredomain.com)",
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
    is_flag=True,
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
    "--out-file", "out_file", required=False, help="location to save the report"
)
@click.command()
def tester(
    cve_id: str,
    directory: str,
    waf_url: str,
    full_report: bool,
    out_file: str,
    format: str,
) -> None:
    """Trigger CVE testing process
    \f
    Triggers the cve testing process using the cve_test class object and then calling the generate_raw().

    Args:
        cve_id: comma separated values for cve(s) to test.
        waf_url: specify a waf other than modsec-crs
        directory: specify directory to store program output
        full_report: Boolean flag to include all tested CVE data in the report. Report only includes Unblocked / Partially blocked CVE data.
        out_file: name for the report file
    """
    if cve_id is not None:
        cve_id=cve_id.split(",")
    test = Cve_tester(cve_id=cve_id, directory=directory, waf_url=waf_url)
    result_directory = test.generate_raw()
    classify = Classifier(
        dir=result_directory, format=format, out_file=out_file, full_report=full_report
    )
    classify.reader()


main.add_command(tester)
