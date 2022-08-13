# Project Seaweed

[![Tests](https://github.com/<your-username>/hypermodern-python/workflows/Tests/badge.svg)](https://github.com/vandanrohatgi/Project-Seaweed/actions?workflow=Tests)

## GSoC meet #9 Summary

Reviewed Github action integration. Now we will be working on scheduling a cron job to trigger weekly (nuclei-templates releases). We will also store all the past reports in a dedicated github repository. We will use that repository to perform analysis of past and current reports to find what changed and when did it change. We will be writing a new command to compare reports in the project. In the report analysis we calculate numbers such as number of CVEs tested, number of blocks, non blocks and partial blocks, what was not blocked before and its being blocked now etc. When we run any github action we also integrate it with slack to get updates.


For anyone interested in the project report: https://docs.google.com/spreadsheets/d/1ElvPa8CAvSg8lwars4tfafokFZy59khLo2Hj_GbRXFM/edit?usp=sharing

Tasks for the week:

1. ~~Set-up slack integration~~
2. ~~Implement report analysis~~
3. ~~Setup Github repo for storing past reports~~
4. Add support for more python versions
5. Also export audit logs from crs and save in the above repo
6. ~~Remove nuclei docker container and use local nuclei installation~~

Notes:

To find unique tags in nuclei templates:

`grep "tags" -r . | cut -d":" -f3 | sed 's/,/\n/g' | sed 's/ //g' | sort | uniq -c | sort -n`

Nuclei identifies HTTP based CVEs using the `requests` keyword in the templates.


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