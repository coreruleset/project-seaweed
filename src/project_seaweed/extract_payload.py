import sys
import bs4
import requests
import re
import click

from . import __version__

#url="https://huntr.dev/bounties/df46e285-1b7f-403c-8f6c-8819e42deb80/"
#url="https://www.exploit-db.com/exploits/50950"

@click.command()
@click.version_option(version=__version__)
@click.option("-u","--url",required=True, help="URL where the PoC is hosted")
def main(url):
    headers={"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:101.0) Gecko/20100101 Firefox/101.0"}
    try:
        response=requests.get(url=url,headers=headers)
        status=response.status_code
        if status!=200:
            raise requests.exceptions.InvalidURL
    except:
        print("URL not reachable!")
        sys.exit(0)
    soup=bs4.BeautifulSoup(response.text,features="html.parser")
    PoC=soup.find('code')
    if PoC!=None:
        PoC=str(PoC.text)
        print(PoC,end="\n\n\n")
        print(re.findall("https?://.*",PoC))
    else:
        print("Unable to find payload in the given URL")