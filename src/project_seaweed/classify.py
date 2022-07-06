"""Identify false negatives in nuclei's report"""
import re
import os
import logging


class Classifier:
    """
    Consists of function to handle false negative classification by going through nuclei response codes.

    Args:
        dir: path to directory where nuclei responses are stored.
    """

    def __init__(self, dir: str) -> None:
        self.dir = f"{dir}/http/"
        # self.regex=re.compile("HTTP\/1\.1\s([^4]\d\d)",re.IGNORECASE)
        self.regex = re.compile("HTTP\/1\.1\s(?!403)\d\d\d", re.IGNORECASE)

    def is_false_negative(self, data: str) -> bool:
        """
        Classifies false negatives

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
        Read contents of the directory, file by file and call false-negtive classification on each file
        """
        for file in os.listdir(self.dir):
            with open(f"{self.dir}{file}", "r") as f:
                try:
                    result = self.is_false_negative(f.read())
                    if result:
                        print("is false negative")
                except UnicodeDecodeError:
                    print("error")
                    pass


# obj= Classifier("/home/vandan/project-seaweed/results")
# obj.reader()
