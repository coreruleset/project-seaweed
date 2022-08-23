"""Class to generate program report"""

import logging
import os
import json
import csv
from collections import OrderedDict
from typing import Dict, List


class cve_details:
    """custom data type to store cve details

    Args:
        cve: CVE Id
    """

    def __init__(self, cve: str, **kwargs: Dict[str, str]) -> None:
        self.cve: str = cve
        self.kwargs: Dict[str, str] = kwargs

    def output(self) -> OrderedDict:
        """Generate a dictionary from CVE details

        Returns:
            OrderedDict: returns an ordered dictionarry to maintin order of insertion of data
        """
        custom_dict = OrderedDict()
        custom_dict["cve"] = self.cve
        custom_dict.update(self.kwargs)
        return custom_dict

    def keys(self) -> list:
        """To return all the keys present in cve_details object

        Returns:
            list: returns a list of attributes of the cve_details object
        """
        return list(self.output().keys())


class Report:
    """Handle report generation functions

    Args:
        format: format for the generated report ( json | csv )
        out_file: Name of the file to be generated. Also used for path of generated file.
    """

    def __init__(self, format: str = "json", out_file: str = None) -> None:
        self.format: str = format
        if out_file is None:
            self.out_file: str = f"{os.getcwd()}/report.{format}"
            logging.info("Report saved at:" + self.out_file)
        else:
            self.out_file: str = out_file
        self.data: List[cve_details] = []

    def add_data(self, data: cve_details) -> None:
        """Add cve_details object to a list"""
        self.data.append(data)

    def gen_file(self) -> None:
        """Generate report file in the specified format

        First generates a list of dictionaries [{},{},{}...] , then writes to the specified format.
        This was done due to loss of data while converting dictionaries to csv files. So the process
        was generalized for both file formats.
        """
        if self.format == "json":
            with open(self.out_file, "w") as f:
                json.dump([row.output() for row in self.data], f)
        elif self.format == "csv":
            with open(self.out_file, "w") as f:
                writer = csv.writer(f)

                writer.writerow(
                    [field for field in self.data[0].keys()]
                )  # write field names at the top of csv using first element

                for row in self.data:
                    writer.writerow(
                        [row.output().get(value, None) for value in row.keys()]
                    )  # fill the following rows with values
