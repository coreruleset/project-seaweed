# Project Seaweed

[![Tests](https://github.com/vandanrohatgi/Project-Seaweed/workflows/Tests/badge.svg)](https://github.com/vandanrohatgi/Project-Seaweed/actions?workflow=Tests)

## GSoC meet #10 Summary

Achieved 10 GSoC meetings (yay!). Reviewed the slackbot and decided to add more informative messages in the bot update. Since the modsec-crs image does not contain the version number of the CRS we will use the latest commit hash to keep track of crs ruleset being used for testing. Right now the reports are under directories in a  (year)/(month)/(day) format. If multiple tests are run on the same day we leave it upto git versioning to keep track instead of adding an identifier to all the reports. Since at paranoia level 4 the audit log files are going to be huge we will not be integrating the extraction of these files in the program itself, instead we will document the process to extract them from the container.


Tasks for the week:

1. ~~Work on Report comparison feature~~
2. ~~Customize slack bot with information from report analysis~~
3. ~~Document the crs audit log collection~~
4. ~~Add CRS commit hash to analysis report~~
5. Fix tests github action
6. Open source license ?

Github repo for project reports and analysis: https://github.com/vandanrohatgi/Seaweed-Reports

Notes:

To find unique tags in nuclei templates:

`grep "tags" -r . | cut -d":" -f3 | sed 's/,/\n/g' | sed 's/ //g' | sort | uniq -c | sort -n`

Nuclei identifies HTTP based CVEs using the `requests` keyword in the templates.

## Fetching CRS logs from the container

This project does not provide the functionality to fetch the logs from CRS container. However, you can use the `--keep-setup` flag to prevent the docker setup (crs container, apache container and docker network). After that you can fetch the audit logs using the following commands.

`docker cp crs-waf:/root/audit.log <path to save log file>`

**Caveat**: If you specify `--keep-setup`, you are responsible for performing the cleanup activity. To do that, just enter the following commands.

`docker stop crs-waf`

`docker stop httpd-server`

`docker network rm seaweed-network`

## Installation

1. **Clone the repository**

`git clone https://github.com/vandanrohatgi/Project-Seaweed.git`

2. **Install poetry** 

Poetry is a tool for dependency management and packaging in Python. 

[https://python-poetry.org/docs/#installation](https://python-poetry.org/docs/#installation)

3. **Install docker**

This project needs docker to setup a local web server, web application firewall. If you're using a custom waf URL for testing, then docker is not needed. 

[https://docs.docker.com/engine/install/](https://docs.docker.com/engine/install/)

5. **Install Nuclei**

The program uses Nuclei to launch attacks. Make sure nuclei is in the path and nuclei templates are installed in the home directory and not a custom directory. Install from here: [https://nuclei.projectdiscovery.io/nuclei/get-started/#nuclei-installation](https://nuclei.projectdiscovery.io/nuclei/get-started/#nuclei-installation)

6. **Select Python version**

The project is tested on Python `3.9.13`. If you have multiple python versions installed, use the following command:

`poetry env use 3.9`

7. **Install the project**

`poetry install`

8. **Finally run the project**

`poetry run project-seaweed`

9. **Get help**

`poetry run project-seaweed --help`

For command specific help

`poetry run project-seaweed tester --help`