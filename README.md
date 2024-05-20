# Project Seaweed

<img src="images/seaweed.png" width="100px" alt="Seaweed">

image: Flaticon.com
    
[![GitHub Workflow Status](https://img.shields.io/github/workflow/status/coreruleset/project-seaweed/CI)]()

Project Seaweed was originally a part of **Google Summer of Code 2022** under the OWASP Foundation Core Rule Set team. Under the guidance of [Felipe Zipitría](https://github.com/fzipi).

Seaweed is fully customizable CI/CD friendly tool created to automate the testing of web application firewalls against various CVE(s). 

It does so by utilising the PoCs provided by [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) from team [Project Discovery](https://github.com/projectdiscovery). Using these beautifully formatted yaml templates we can test firewalls as well as generate metadata for the firewall testing process. At the end of testing we receive a small summary notification in the form of a slack message.

![](/images/flowchart_white_back.drawio.png)

## Features

1. **Parameters**

There are two ways to modify the tool behaviour. You can either use the CLI flags or specify environment variables.

**CLI:**

```
Usage: project-seaweed [OPTIONS]
```

**Environment variables:**

Variable     | Default  | Description
---|---|---
WAF_IMAGE | owasp/modsecurity-crs:apache | Docker image to use for firewall setup
WEB_SERVER_IMAGE | httpd:latest| Docker image to use for web server setup
WAF_NAME |crs-waf| Docker container name for the firewall
WEB_SERVER_NAME |httpd-server| Docker container name for the web server
NETWORK_NAME | seaweed-network|Name of docker network
NUCLEI_THREADS | 10 |Speed of testing (higher threads lead to poor testing)
CVE_ID| None | CVE IDs to test
WAF_URL | None | Firewall URL if not setting up local docker
OUT_DIR | /tmp | Raw request / response output from nuclei
FULL_REPORT | False | Include blocked CVEs in the report
KEEP_SETUP | False | Keep the local docker setup (Usually for extracting audit logs from container)
OUT_FILE | report.json | name and path of the output report
TAG | All | Attack types to test ('lfi', 'xss', 'fileupload', 'xxe', 'injection', 'traversal', 'disclosure', 'auth-bypass', 'ssrf', 'sqli', 'oast', 'rce')
FORMAT | json | Report format
REPO_OWNER | None | Needed for working in a CI/CD environment


2. **Docker Setup**

By default, a docker setup containing of ModSec-CRS reverse proxy container (Firewall) and an apache web server container is created and both the containers are attached to a network. This was done to have a local firewall setup. This has 2 advantages:

- Removes network latency and hence quicker testing
- Doesn't disturb the remote firewall

Of course, this behaviour can be changed and you can specify a remote URL and avoid setting up the local docker setup.

3. **Report generation**

After Nuclei has finished launching the attacks on the firewall, we store the requests and responses that were made. You can specify a directory if you want to see this raw data, otherwise it is stored inside a temporary directory. 

We then use this data to figure out if the CVE is blocked or not. If the attack is multi-staged we calculate how much of the attack was blocked (blocked requests / total requests). Based on this a report is generated. 

You can specify the report format to be either `csv` or `json`.

![](/images/report.png)

5. **Scan History**

If you're using the tool in a CI/CD environment like Github Actions, a repository named `seaweed-reports` is needed which records all the past scans and their respective artifacts. The github action tests various types of common web CVE(s) such as xss, rce, sqli etc. along with a full test of all the available CVE(s) in the nuclei templates.

You can modify this behaviour according to the needs by changing the matrix of Github Action.

6. **Slack integration**

After the testing is finished, a message is sent to the defined channel on slack with a small summary.

![](/images/slack.png)

Commits:
- [7fdfac397e9ba5e6925577264c5cffcc9106fc20](https://github.com/coreruleset/project-seaweed/commit/7fdfac397e9ba5e6925577264c5cffcc9106fc20)
- [973cf52b3830e6c85d2e46a884a34dac9c62350f](https://github.com/coreruleset/project-seaweed/commit/973cf52b3830e6c85d2e46a884a34dac9c62350f)

7. **Report comparison**

TBD

## Usage

**Installation**

1. **Clone the repository**

`git clone https://github.com/coreruleset/project-seaweed.git`

3. **Install docker**

This project needs docker to setup a local web server, web application firewall. If you're using a custom waf URL for testing, then docker is not needed. 

[https://docs.docker.com/engine/install/](https://docs.docker.com/engine/install/)

5. **Install Nuclei**

The program uses Nuclei to launch attacks. Make sure nuclei is in the path and nuclei templates are installed in the home directory and not a custom directory. Install from here: [https://nuclei.projectdiscovery.io/nuclei/get-started/#nuclei-installation](https://nuclei.projectdiscovery.io/nuclei/get-started/#nuclei-installation)

6. **Install the project**

`go build`

7. **Finally run the project**

`./project-seaweed -o output`
