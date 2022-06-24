# Project Seaweed

## GSoC meet #4 Summary

Reviewed the python project setup. Went through the entire false negatives classification process and decided to improve our classification methods and automate the entire process which was being performed manually. Will be using libraries such as docker SDK for python & py-nuclei to achieve this. 
Reviewed the analyses of tools such as vulcrawler & xlocate. Reached the decision to keep them as an extra source of information for now.

Tasks for the week

1. Continue setting up Python project: typing, documentation, CI/CD
2. Pure python implementation to:
- create CRS docker infra
- running nuclei CVEs

Extra Tasks

- identify false negatives
- Classify false negatives according to severity and type of attack
- generate report

Progress

Created docker modsec-crs infrastructure in python and ran nuclei CVE templates against it. Finally, fetched the responses for further processing.

notes:

nuclei looks for "requests" keyword in templates to identify HTTP CVEs.
