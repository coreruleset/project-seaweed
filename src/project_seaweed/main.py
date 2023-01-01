"""Entrypoint program & CLI interface"""

import os
import logging
import click
from datetime import datetime, timezone
from project_seaweed import __version__
from project_seaweed.classify import Classifier
from project_seaweed.cve_tester import Cve_tester
from project_seaweed.util import update_analysis
from project_seaweed.report_analyzer import analyze


@click.group()
@click.version_option(version=__version__)
@click.option(
    "-l",
    "--log-level",
    "level",
    type=click.Choice(["debug", "info", "warning"], case_sensitive=False),
    help="log level",
    default="warning",
    required=False,
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
    required=False,
    help="Includes blocked attack's info in the report (bigger report)",
)
@click.option(
    "--keep-setup",
    "keep_setup",
    is_flag=True,
    required=False,
    help="Stops automatic removal of docker setup",
)
@click.option(
    "--format",
    "format",
    type=click.Choice(["json", "csv"], case_sensitive=True),
    default="json",
    show_default=True,
    required=False,
    help="format for report",
)
@click.option(
    "--out-file", "out_file", required=False, help="Name & location of the report file"
)
@click.option(
    "--tag",
    required=False,
    help="lfi,xss,fileupload,xxe,injection,traversal,disclosure,auth-bypass,ssrf,sqli,oast,rce"
)
@click.option(
    "--include-all",
    "include_all",
    is_flag=True,
    required=False,
    help="Generate a report with all CVEs with specified attacks"
)
@click.command()
def tester(
    cve_id: str,
    directory: str,
    waf_url: str,
    full_report: bool,
    out_file: str,
    format: str,
    tag: str,
    keep_setup: bool,
    include_all: bool
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
        tag: comma separated values for type of attack to test ('lfi', 'xss', 'fileupload', 'xxe', 'injection', 'traversal', 'disclosure', 'auth-bypass', 'ssrf', 'sqli', 'oast', 'rce')
        format: format for the report
        keep_setup: Boolean flag to retain docker setup
        include_all: Boolean Generate a report with all CVEs with specified attacks
    """

    cve_id = os.environ.get(
        "CVE_ID", default=cve_id
    )  # fetch value from env if set, else use CLI param
    cve_id = (
        cve_id if bool(cve_id) else None
    )  # bool('') equates to False. For cases when, env var is set but empty (GithubActions)

    waf_url = os.environ.get("WAF_URL", default=waf_url)
    waf_url = waf_url if bool(waf_url) else None

    directory = os.environ.get("OUT_DIR", default=directory)
    directory = directory if bool(directory) else None

    full_report = bool(os.environ.get("FULL_REPORT", default=full_report))

    keep_setup = bool(os.environ.get("KEEP_SETUP", default=keep_setup))

    out_file = os.environ.get("OUT_FILE", default=out_file)

    tag = os.environ.get("TAG", default=tag)
    tag = tag if bool(tag) else None

    format = os.environ.get("FORMAT", default=format)
    format = format if bool(format) else None

    include_all = bool(os.environ.get("INCLUDE_ALL", default=include_all))


    update_analysis(
        date=datetime.now(timezone.utc).strftime("%d %b %Y"),
        time=datetime.now(timezone.utc).strftime("%H:%M:%S UTC"),
    )

    if cve_id is not None:
        cve_id = cve_id.split(",")

    test = Cve_tester(
        cve_id=cve_id,
        directory=directory,
        waf_url=waf_url,
        tag=tag,
        keep_setup=keep_setup,
        include_all=include_all
    )
    result_directory = test.generate_raw()
    classify = Classifier(
        dir=result_directory, format=format, out_file=out_file, full_report=full_report, tags=tag, include_all=include_all
    )
    classify.reader()

    update_analysis(
        cve_id=cve_id,
        directory=directory,
        waf_url=waf_url,
        tag=tag,
        full_report=full_report,
        out_file=out_file,
        format=format,
    )


@click.option(
    "-d1",
    "--date1",
    default="latest",
    help="Primary report date for comparison. Ex: 2022/Sep/15",
)
@click.option(
    "-d2", "--date2", help="Secondary report date for comparison. Ex: 2022/Aug/15"
)
@click.option("-t", "--tag", default="", help="Type of report (attack type)")
@click.command
def analyzer(date1: str, date2: str, tag: str) -> None:
    analyze(date1=date1, date2=date2, tag=tag)


main.add_command(tester)
main.add_command(analyzer)
