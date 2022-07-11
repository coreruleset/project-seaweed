"""Identify false negatives in nuclei's report"""
import re
import os

# import logging


class Classifier:
    """
    Consists of function to handle false negative classification by going through nuclei response codes.

    Args:
        dir: path to directory where nuclei responses are stored.
    """

    def __init__(self, dir: str) -> None:
        self.dir = f"{dir}/http/"
        # self.regex=re.compile("HTTP\/1\.1\s([^4]\d\d)",re.IGNORECASE)
        self.regex = re.compile(r"HTTP\/1\.1\s(?!403)\d{3}", re.IGNORECASE)
        self.cve_regex = re.compile(r"(CVE-\d{4}-\d{1,})")
        self.cve_file_regex = re.compile(r"(CVE_\d{4}_\d{1,})")

    def is_false_negative(self, data: str) -> bool:
        """Classifies false negatives

        Args:
            data: data in string format, consisting of requests & response data

        Returns:
            bool: True if attack was a false-negative, False otherwise.
        """
        matches = re.search(self.regex, data)
        if matches is not None:
            return True
        else:
            return False

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
                if self.is_false_negative(data):
                    print(cve)


# obj= Classifier("/home/vandan/project-seaweed/results")
# obj.reader()
