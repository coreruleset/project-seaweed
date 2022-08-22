"""Class to process reports and generate insight"""

"""comparison operation will take month of the last report (latest by default) and the freshly generated
report. will compare the two jsons and print the insight in a csv."""

import logging
import sys
from typing import Dict
import requests
import yaml
import re
import difflib

attacks = [
    "lfi",
    "xss",
    "fileupload",
    "xxe",
    "injection",
    "traversal",
    "disclosure",
    "auth-bypass",
    "ssrf",
    "sqli",
    "oast",
    "rce",
]

file_url:str="https://raw.githubusercontent.com/vandanrohatgi/Seaweed-Reports/main/{}/{}Analysis.yaml"
latest_scan:str="https://raw.githubusercontent.com/vandanrohatgi/Seaweed-Reports/main/latest.txt"

date_format=re.compile(r"\d{4}/[a-zA-Z]{3}/[1-31]{1}")

def fetch_latest_test():
    response:str=requests.get(latest_scan)
    dir:str=response.text.strip()
    return dir

def dir_exists(dir):
    response=requests.get(file_url.format(dir+"#",""))
    if response.status_code != 200:
        return False
    else:
        return True


def analyze(date1:str="",date2:str="",tag:str="") -> None:
    """
    Read analysis files stored in github and display it's contents or compare the contents of two analysis

    Args:
        date1: date in the format (year/month/date). by default fetches the latest test analysis
        date2: date in the format (year/month/date). date for the report we want to compare with.
        tag: type of attack analysis. By default uses the full test analysis report.
    """

    if date1 == "latest":
        date1=fetch_latest_test()

    response1:str=requests.get(file_url.format(date1,tag)).text
    response2:str=requests.get(file_url.format(date2,tag)).text

    for line in difflib.unified_diff(
        response2.split("\n"),response1.split("\n"), fromfile=f"{tag}Analysis.yaml {date2}",
        tofile=f"{tag}Analysis.yaml {date1}", lineterm=''):
        print(line)

"""    if bool(date2) is False:
        response:str=requests.get(file_url.format(date1,tag)).text
        analysis_data:Dict=yaml.load(response,Loader=yaml.SafeLoader)
        for key in analysis_data.keys():
            print(key,analysis_data[key],sep=":")
    else:
        response1:str=requests.get(file_url.format(date1,tag)).text
        response2:str=requests.get(file_url.format(date2,tag)).text
        analysis_data1:Dict=yaml.load(response1,Loader=yaml.SafeLoader)
        analysis_data2:Dict=yaml.load(response2,Loader=yaml.SafeLoader)
        for key in analysis_data1.keys():
            analysis_data1[key]"""