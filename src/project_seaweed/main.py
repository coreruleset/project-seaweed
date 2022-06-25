import click
from .extract_payload import extract
from . import __version__
from .test_cve import cve_tester


@click.command()
@click.version_option(version=__version__)
@click.option("-u", "--url", required=False, help="URL where the PoC is hosted")
def main(url: str) -> None:
    if url is not None:
        extract(url=url)
    else:
        test = cve_tester()
        test.generate_raw()


"""@click.command()
@click.option("-u", "--url", required=False, help="URL where the PoC is hosted")
def extract_payload(url):
    extract(url=url)
"""
