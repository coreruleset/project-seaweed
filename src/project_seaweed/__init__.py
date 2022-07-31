"""Project Seaweed (GSoC 2022)"""
from .util import fetch_nuclei_templates, printer

__version__ = "0.1.0"

printer(msg="Fetching Nuclei templates...")
fetch_nuclei_templates()
