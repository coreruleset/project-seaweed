# Project Seaweed

<img src="images/seaweed.png" width="100px" alt="Seaweed">

image: Flaticon.com

[![GitHub Workflow Status](https://img.shields.io/github/workflow/status/coreruleset/project-seaweed/CI)]()

Project Seaweed was originally a part of **Google Summer of Code 2022** under the OWASP Foundation Core Rule Set team.
Under the guidance of [Felipe Zipitría](https://github.com/fzipi).

Seaweed is fully customizable CI/CD friendly tool created to automate the testing of web application firewalls against
various CVE(s).

It does so by utilising the PoCs provided by [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)
from team [Project Discovery](https://github.com/projectdiscovery). Using these beautifully formatted yaml templates we
can test firewalls as well as generate metadata for the firewall testing process. At the end of testing we receive a
small summary notification in the form of a slack message.

![](/images/flowchart_white_back.drawio.png)

## Features

1. **Parameters**

There are two ways to modify the tool behaviour. You can either use the CLI flags or specify environment variables.

**CLI:**

```
❯ ./project-seaweed --help
Parses Nuclei test files output

Usage:
  seaweed [flags]

Flags:
  -f, --format format   format to output the results; can be 'github' (default) or 'json' (default github)
  -h, --help            help for seaweed
  -o, --output string   path to find output trace files (default ".")
```

2. **Docker Setup**

By default, a docker setup containing of ModSec-CRS reverse proxy container (Firewall) and an apache web server
container is created and both the containers are attached to a network. This was done to have a local firewall setup.
This has 2 advantages:

- Removes network latency and hence quicker testing
- Doesn't disturb the remote firewall

3. **Report generation**

After Nuclei has finished launching the attacks on the firewall, we store the requests and responses that were made. You
can specify a directory if you want to see this raw data, otherwise it is stored inside a temporary directory.

We then use this data to figure out if the CVE is blocked or not. If the attack is multi-staged we calculate how much of
the attack was blocked (blocked requests / total requests). Based on this a report is generated.

You can specify the report format to be either `github` (default) or `json`.

5. **Scan History**

The recommended usage of this tool in a CI/CD environment like Github Actions.
The github action tests various types of common web CVE(s) such as xss, rce, sqli etc. along with a full test of all the available CVE(s) in the nuclei templates.

6. **Slack integration**

After the testing is finished, a message is sent to the defined channel on slack with a small summary.

![](/images/slack.png)

7. **Report comparison**

TBD

## Usage

**Installation**

1. **Clone the repository**

`git clone https://github.com/coreruleset/project-seaweed.git`

3. **Install docker**

This project needs docker to setup a local web server, web application firewall. If you're using a custom waf URL for
testing, then docker is not needed.

[https://docs.docker.com/engine/install/](https://docs.docker.com/engine/install/)

6. **Install the project**

You need go installed on your system to build the project.

`go build`

7. **Finally run the project**

```
docker compose up
```
This will start the docker containers and run the tests. The results will be by default in a folder called `output`.

Now run the reporting tool using the following command:

`./project-seaweed -o output`
