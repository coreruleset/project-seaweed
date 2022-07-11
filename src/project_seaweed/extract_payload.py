"""Extract exploit payload from webpage URL"""

import logging
import sys
import bs4
import requests.exceptions as req_ex
import requests

# import re


def extract(url: str) -> str:
    """Function to extract code/ payload from exploit PoC urls. Performs site availability check by sending HEAD request.

    Args:
        url: url where PoC is hosted.

    Returns:
        extracted data from the PoC webpage.

    Raises:
        InvalidURL: if response status code of the provided URl is not 200 OK.

    Example:
        >>> from project_seaweed.extract_payload import extract
        >>> extract("https://huntr.dev/bounties/df46e285-1b7f-403c-8f6c-8819e42deb80/")
            Steps to reproduce:
            Naviagate the below URL
            URL: https://demo.contao.org/contao/"><svg//onload=alert(112233)>
            Here Some Image POC Attached
            ['https://demo.contao.org/contao/"><svg//onload=alert(112233)>']
    """
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:101.0) Gecko/20100101 Firefox/101.0"  # noqa E501
    }
    try:
        response = requests.head(url=url, headers=headers)
        status = response.status_code
        if status != 200:
            logging.debug(f"status code for {url}: {status}")
            raise req_ex.InvalidURL
    except (req_ex.ConnectTimeout, req_ex.InvalidURL):
        sys.exit("URL not reachable!")
    webpage = requests.get(url=url, headers=headers)
    soup = bs4.BeautifulSoup(webpage.text, features="html.parser")
    PoC = soup.find("code")
    if PoC is not None:
        PoC = str(PoC.text)
        # return re.findall("https?://.*", PoC)
        print(PoC)
        return PoC
    else:
        print("Unable to find payload in the given URL")
        return None
