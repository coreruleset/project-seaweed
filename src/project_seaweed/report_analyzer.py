"""Process reports and generate insight"""

import requests
import difflib
import os

repo_owner=os.environ.get("REPO_OWNER", default='coreruleset')

file_url: str = "https://raw.githubusercontent.com/{}/Seaweed-Reports/main/{}/{}Artifact/{}Analysis.yaml"
latest_scan: str = (
    "https://raw.githubusercontent.com/{}/Seaweed-Reports/main/latest.txt"
)


def fetch_latest_test() -> str:
    """Fetches the latest test date from latest.txt

    Returns:
        str: directory where the latest test results are stored
    """
    response: str = requests.get(latest_scan.format(repo_owner))
    dir: str = response.text.strip()
    return dir


def analyze(date1: str = "", date2: str = "", tag: str = "") -> None:
    """
    Read analysis files stored in github and display it's contents or compare the contents of two analysis

    Args:
        date1: date in the format (year/month/date). by default fetches the latest test analysis
        date2: date in the format (year/month/date). date for the report we want to compare with.
        tag: type of attack analysis. By default uses the full test analysis report.
    """

    if date1 == "latest":
        date1 = fetch_latest_test()

    response1: str = requests.get(file_url.format(repo_owner,date1, tag, tag)).text
    response2: str = requests.get(file_url.format(repo_owner,date2, tag, tag)).text

    for line in difflib.unified_diff(
        response2.split("\n"),
        response1.split("\n"),
        fromfile=f"{tag}Analysis.yaml {date2}",
        tofile=f"{tag}Analysis.yaml {date1}",
        lineterm="",
    ):
        print(line)
