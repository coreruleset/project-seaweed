# Project Seaweed

## GSoC meet #5 Summary

Reviewed the progress regarding creating Crs-modsec docker setup and launching exploits using nuclei docker containers. @felipe is going try and setup the project on his system and later open issues on [Project github repo](https://github.com/vandanrohatgi/Project-Seaweed) regarding any changes / improvements. 

Tasks for the week

1. Continue setting up Python project following [https://medium.com/@cjolowicz/hypermodern-python-d44485d9d769]:
- Documentation
- CI/CD
2. Continue working on:
- Provide a CLI parameter to define type of cve to lunch (XSS, SQLi etc.)
- Create project setup README.md
- identify false negatives

extra Tasks:

- Classify false negatives according to severity and type of attack
- generate report

Progress:
- Added docstring Documentation to functions and classes.
- Found unique attack types from tags in nuclei templates
- Added installation README

Notes:

To find unique tags in nuclei templates:

`grep "tags" -r . | cut -d":" -f3 | sed 's/,/\n/g' | sed 's/ //g' | sort | uniq -c | sort -n`

Right now all nuclei components were inside the nuclei container. But to use tags and CVE metadata we will need to query the nuclei template repository. Should we just make a local copy of it or make requests to github nuclei-template repository?

To classify false negatives, we consider any response code other than 403 as a bypass. The config on crs-modsec docker container shows that by default all phases return 403 upon attack detection.
## Installation

1. Clone the repository

`git clone https://github.com/vandanrohatgi/Project-Seaweed.git`

2. Install poetry

[https://python-poetry.org/docs/#installation](https://python-poetry.org/docs/#installation)

3. Install docker

[https://docs.docker.com/engine/install/](https://docs.docker.com/engine/install/)

4. Select Python version

The project is tested on Python `3.9.13`. If you have multiple python versions installed, use the following command:

`poetry env use 3.9`

5. Install the project

`poetry install`

6. Finally try to run

`poetry run project-seaweed`