"""Class to generate program report"""

import os
import json
import csv
from collections import OrderedDict

class cve_details():
    """custom data type to store cve details
    
    Args:
        cve: CVE Id
        severity: severity of the CVe in question
        attack_type: type of attack launched by CVE
    """
    def __init__(self,cve:str,**kwargs) -> None:
        self.cve=cve
        self.kwargs=kwargs
    
    def output(self) -> OrderedDict:
        """Generate a dictionary from CVE details
        
        Returns:
            OrderedDict: returns an ordered dictionarry to maintin order of insertion of data
        """
        custom_dict= OrderedDict()
        custom_dict["cve"]=self.cve
        custom_dict.update(self.kwargs)
        return custom_dict

    def keys(self) -> None:
        """To return all the keys present in cve_details object
        
        Returns:
            list: returns a list of attributes of the cve_details object
        """
        return list(self.output().keys())

class Report():
    """Handle report generation functions
    
    Args:
        format: format for the generated report ( json | csv )
        out_file: Name of the file to be generated. Also used for path of generated file.
    """
    def __init__(self,format:str="json",out_file:str=None) -> None:
        self.format=format
        if out_file is None:
            self.out_file=f"{os.getcwd()}/report.{format}"
        else:
            self.out_file=out_file
        self.data=[]

    def add_data(self,data:cve_details) -> None:
        """Add cve_details object to a list"""
        self.data.append(data)

    def gen_file(self)->None:
        """Generate report file in the specified format
        
        First generates a list of dictionaries [{},{},{}...] , then writes to the specified format.
        This was done due to loss of data while converting dictionaries to csv files. So the process 
        was generalized for both file formats.
        """
        if self.format == "json":
            with open(self.out_file,"w") as f:
                json.dump([row.output() for row in self.data],f)
        elif self.format == "csv":
            with open(self.out_file,"w") as f:
                writer=csv.writer(f)
                writer.writerow([field for field in self.data[0].keys()]) # write field names at the top of csv using first element
                for row in self.data:
                    writer.writerow([row.output().get(value,None) for value in row.keys()]) # fill the following rows with values
