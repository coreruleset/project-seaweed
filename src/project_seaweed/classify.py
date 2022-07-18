"""Identify false negatives in nuclei's report"""
import re
import os
from typing import Union
from .report_generator import Report, cve_details
from .util import parse_template


class Classifier:
    """
    Consists of function to handle false negative classification by going through nuclei response codes.

    Args:
        dir: path to directory where nuclei responses are stored.
        format: foramt for the report (json | csv)
        out_file: file path for the report
        full_report: Include all tested CVE details. Includes CVEs that were blocked. Report only reflects
                     unblocked or partially blocked CVEs by default.
    """

    def __init__(
        self, dir: str, format: str, out_file: str, full_report: bool = False
    ) -> None:
        self.dir = f"{dir}/http/"
        self.full_report = full_report
        self.forbidden_regex = re.compile(
            r"HTTP\/1\.1\s(?!403)\d{3}"
        )  # regex for 403 Forbidden responses
        self.request_regex = re.compile(r"HTTP\/1\.1\s\d{3}")
        self.cve_regex = re.compile(r"(CVE-\d{4}-\d{1,})")
        self.cve_file_regex = re.compile(r"(CVE_\d{4}_\d{1,})")
        self.report = Report(format=format, out_file=out_file)

    def find_block_type(self, data: str) -> Union[bool, int]:
        """find if an attack was blocked, not blocked or partially blocked

        Args:
            data: data in string format, consisting of requests & responses

        Returns:
            bool: Block status (True | False)
            int: percentage of the attack blocked
        """
        total_requests = len(re.findall(self.request_regex, data))
        blocked_requests = len(re.findall(self.forbidden_regex, data))
        if total_requests == blocked_requests:
            output = True
            block_percent = 100
        elif blocked_requests == 0:
            output = False
            block_percent = 0
        else:
            block_percent = (blocked_requests / total_requests) * 100
            output = False

        return output, block_percent

    def reader(self) -> None:
        """
        Read contents of the directory, file by file and call false-negative classification on each file
        """
        files = [
            file
            for file in os.listdir(self.dir)
            if re.search(self.cve_file_regex, file) is not None
        ]
        for file in files:
            with open(f"{self.dir}{file}", "rb") as f:
                # ignore all weird characters that may be found in an attack. We only need the response codes.
                data = f.read().decode("utf-8", errors="ignore")
            cve = re.search(self.cve_regex, data).group(0)
            block_status, percent = self.find_block_type(data=data)
            if block_status is True and self.full_report is False:
                continue
            self.report.add_data(
                cve_details(
                    cve=cve,
                    blocked=block_status,
                    block_percentage=percent,
                    **parse_template(cve),
                )
            )
        self.report.gen_file()
