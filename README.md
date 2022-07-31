# Project Seaweed

## GSoC meet #8 Summary

Discussed about the program output and it's formatting for various environments (terminal, Github Actions, Gitlab ...). Reviewed the project report. Since the basic program is ready, we will now start to take the project to github actions.


For anyone interested in the project report: https://docs.google.com/spreadsheets/d/1ElvPa8CAvSg8lwars4tfafokFZy59khLo2Hj_GbRXFM/edit?usp=sharing

Tasks for the week:

1. ~~Work on logger output~~
2. ~~Work on a basic github action integration~~
3. ~~Add more attack types to google spreadsheet~~


Doubts:

1. ~~Logger levels~~
2. ~~How to test / mock a waf url~~
3. ~~Nuclei templates in project root~~
5. ~~Github action flow~~
6. ~~gsoc dashboard not getting updated.~~
7. Let the user setup Nuclei? file permission errors, nuclei templates version mismatches, nuceli-templates fetch...


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