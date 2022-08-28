Installation
===============
.. contents::
    :local:
    :backlinks: none

1. **Clone the repository**

`git clone https://github.com/coreruleset/Project-Seaweed.git`

2. **Install poetry** 

Poetry is a tool for dependency management and packaging in Python. 

`https://python-poetry.org/docs/#installation <https://python-poetry.org/docs/#installation>`_

3. **Install docker**

This project needs docker to setup a local web server, web application firewall. If you're using a custom waf URL for testing, then docker is not needed. 

`https://docs.docker.com/engine/install/ <https://docs.docker.com/engine/install/>`_

5. **Install Nuclei**

The program uses Nuclei to launch attacks. Make sure nuclei is in the path and nuclei templates are installed in the home directory and not a custom directory. 

Install from here: `https://nuclei.projectdiscovery.io/nuclei/get-started/#nuclei-installation <https://nuclei.projectdiscovery.io/nuclei/get-started/#nuclei-installation>`_

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