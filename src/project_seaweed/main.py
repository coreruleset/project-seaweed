import click
from .extract_payload import extract
from . import __version__
from .test_cve import cve_tester


@click.group()
@click.version_option(version=__version__)
def main() -> None:
    pass


@click.command()
def tester() -> None:
    test = cve_tester()
    test.generate_raw()


@click.command()
@click.option("-u", "--url", required=False, help="URL where the PoC is hosted")
def extract_payload(url: str) -> None:
    extract(url=url)


main.add_command(tester)
main.add_command(extract_payload)
