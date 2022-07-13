# Project Seaweed

## GSoC meet #6 Summary

Reviewed the progress. Decided to clone the entire nuclei-templates github repo to use for processing instead of writing code for querying / downloading files. For false negative classification, along with 403 response, we count the number of request sent and count the number of 403 received, then classify attacks as blocked, not blocked and partial block. To find unique attack types we choose top 20 common occuring attacks from nuclei tags and create a list containing just the attack tags (xss,sqli,lfi...). Adapt a unit test based approach instead of calling classes and functions separately to see if they work and stop working like a mess that I am.

Tasks for the week

1. Improve project setup README.
2. Improve classification algorithm.
3. Create list of unique attacks for runnning PoCs.
4. stop procrastinating on writing tests.


Progress:


Notes:

To find unique tags in nuclei templates:

`grep "tags" -r . | cut -d":" -f3 | sed 's/,/\n/g' | sed 's/ //g' | sort | uniq -c | sort -n`

Nuclei identifies HTTP based CVEs using the `requests` keyword in the templates.


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