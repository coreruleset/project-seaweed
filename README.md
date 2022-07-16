# Project Seaweed

## GSoC meet #6 Summary

Reviewed the progress. Decided to clone the entire nuclei-templates github repo to use for processing instead of writing code for querying / downloading files. For false negative classification, along with 403 response, we count the number of request sent and count the number of 403 received, then classify attacks as blocked, not blocked and partial block. To find unique attack types we choose top 20 common occuring attacks from nuclei tags and create a list containing just the attack tags (xss,sqli,lfi...). Adapt a unit test based approach instead of calling classes and functions separately to see if they work and stop working like a mess that I am.

Tasks for the week

1. Improve project setup README.
2. Improve classification algorithm.
3. Create list of unique attacks for runnning PoCs.
4. stop procrastinating on writing tests.


Progress:

1. Added tests for report generator
2. Improved classifer logic
3. Improved Installation guide and CLI help
4. Extracted attack tags from nuclei

Notes:

To find unique tags in nuclei templates:

`grep "tags" -r . | cut -d":" -f3 | sed 's/,/\n/g' | sed 's/ //g' | sort | uniq -c | sort -n`

valid attacks: "lfi,xss,fileupload,xxe,injection,traversal,disclosure,auth-bypass,ssrf,sqli,oast,rce"
Nuclei identifies HTTP based CVEs using the `requests` keyword in the templates.


## Installation

1. **Clone the repository**

`git clone https://github.com/vandanrohatgi/Project-Seaweed.git`

2. **Install poetry** 

Poetry is a tool for dependency management and packaging in Python. 

[https://python-poetry.org/docs/#installation](https://python-poetry.org/docs/#installation)

3. **Install docker**

This project needs docker to setup a local web server, web application firewall and nuclei.

[https://docs.docker.com/engine/install/](https://docs.docker.com/engine/install/)

4. **Select Python version**

The project is tested on Python `3.9.13`. If you have multiple python versions installed, use the following command:

`poetry env use 3.9`

5. **Install the project**

`poetry install`

6. **Finally run the project**

`poetry run project-seaweed`

7. **Get help**

`poetry run project-seaweed --help`

For command specific help

`poetry run project-seaweed tester --help`