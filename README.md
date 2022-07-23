# Project Seaweed

## GSoC meet #7 Summary

Reviewed the progress (It went great). Right now the report shows a boolean if attack was blocked and % of attack blocked if partial block. To improve readability, we come up with better ways to represent information (Blocked | Not Blocked | Partial Block). To better understand the project reports, Export them as csv and create google sheets for various attack types. This will give us an initial overview of CRS and attack type relationships.

Tasks for the week

1. ~~Write integration tests for main~~ (How to test / mock a waf url)
2. ~~Improve block indicators in report~~
3. ~~implement attack types in the project~~
4. ~~Create a google sheet from the report of various attacks~~


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