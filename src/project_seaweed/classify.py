"""Identify false negatives in nuclei's report"""
import re
import os
from .report_generator import Report, cve_details
from .util import parse_template


class Classifier:
    """
    Consists of function to handle false negative classification by going through nuclei response codes.

    Args:
        dir: path to directory where nuclei responses are stored.
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

    """def is_false_negative(self, data: str) -> bool:
        #Classifies false negatives

        Args:
            data: data in string format, consisting of requests & response data

        Returns:
            bool: True if attack was a false-negative, False otherwise.
        #
        matches = re.search(self.regex, data)
        if matches is not None:
            return True
        else:
            return False"""

    def find_block_type(self, data: str) -> str:
        """find if an attack was blocked, not blocked or partially blocked

        Args:
            data: data in string format, consisting of requests & responses

        Returns:
            str: Block status (Blocked | Not Blocked | Partial Block) (blocked requests / total requests)
        """
        total_requests = len(re.findall(self.request_regex, data))
        blocked_requests = len(re.findall(self.forbidden_regex, data))
        if total_requests == blocked_requests:
            output = f"Blocked ({total_requests})"
        elif blocked_requests == 0:
            output = f"Not Blocked ({total_requests})"
        else:
            output = f"Partial Block ({blocked_requests}/{total_requests})"

        return output

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
            block_type = self.find_block_type(data=data)
            self.report.add_data(
                cve_details(cve=cve, block_type=block_type, **parse_template(cve))
            )
        self.report.gen_file()
