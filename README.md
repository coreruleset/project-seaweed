## GSoC meet #12 Summary

Decided to move the project and components to CRS org. After which testing is needed to be performed for the whole project and slack integration. For submission to GSoC we need a URL which hosts a pdf or blog outining the work done and work remaining. 

Tasks for the week:

1. Work on GSoC work report
2. Fix / improve any code or documentation as needed
3. Test working of the project after switching the project to CRS org

Notes:

To find unique tags in nuclei templates:

`grep "tags" -r . | cut -d":" -f3 | sed 's/,/\n/g' | sed 's/ //g' | sort | uniq -c | sort -n`

Nuclei identifies HTTP based CVEs using the `requests` keyword in the templates.


# Project Seaweed

![](/images/seaweed.png 250x250)

<sub><sup>image: Flaticon.com</sup></sub>

Project Seaweed is a part of **Google Summer of Code 2022** under the OWASP Foundation Core Rule Set team. Under the guidance of [Felipe Zipitría](https://github.com/fzipi).

Seaweed is fully customizable CI/CD friendly tool created to automate the testing of web application firewalls against various CVE(s) so that you don't have to. 

It does so by utilising the PoCs provided by nuclei-templates from team Project Discovery. Using these beautifully formatted yaml templates we can test firewalls as well as generate metadata for the firewall testing process. At the end of testing we receive a small summary notification in the form of a slack message.

## Features

1. **Parameters**

There are two ways to modify the tool behaviour. You can either use the CLI flags or specify environment variables.

![](images/cli.png)

### Environment variables

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
TAG | None | Attack types to test (XSS, SQLi, RCE ...)
FORMAT | json | Report format
REPO_OWNER | None | Needed for working in a CI/CD environment

2. **Docker Setup**

By default, a docker setup containing of Modsec-CRS reverse proxy container (Firewall) and an apache web server container is created and both the containers are attached to a network. This was done to have a local firewall setup. This has 2 advantages:

- Removes network latency and hence quicker testing
- Doesn't disturb the remote firewall

Ofcourse, this behaviour can be changed and you can specify a remote URL and avaoid setting up the local docker setup.

This feature was achieved using docker-python SDK.

3. **Report generation**

After Nuclei has finished launching the attacks on the firewall, we store the requests and responses that were made. You can specify a directory if you want to see this raw data, otherwise it is stored inside a temporary directory. 

We then use this data to figure out if the CVE is blocked or not. If the attack is multi-staged we calculate how much of the attack was blocked (blocked requests / total requests). Based on this a report is generated. 

You can specify the report format to be either `csv` or `json`.

![](/images/report.png)

4. **Testing analysis**

Throughout the whole process a `yaml` file is maintained which records various metrics and metadata such as blocked CVE(s), version of firewall used, environment variables etc. This file is then later used for comparing the results of two various scans.

![](/images/analysis.png)

5. **Scan History**

If you're using the tool in a CI/CD environment like Github Actions, a repository named `seaweed-reports` is needed which records all the past scans and their respective artifacts. The github action tests varous types of common web CVE(s) such as xss, rce, sqli etc. along with a full test of all the available CVE(s) in the nuclei templates. You can modify this behaviour according to the needs by changing the matrix of Github Action.

The Directory structure looks like this:

```
Seaweed-Reports/
├── 2022
│   └── Aug
│       ├── 23
│       │   ├── rce-artifact
│       │   │   ├── rceAnalysis.yaml
│       │   │   └── rceReport.csv
│       │   ├── sqli-artifact
│       │   │   ├── sqliAnalysis.yaml
│       │   │   └── sqliReport.csv
│       └── 28
│           ├── rceArtifact
│           │   ├── rceAnalysis.yaml
│           │   └── rceReport.csv
│           ├── sqliArtifact
│           │   ├── sqliAnalysis.yaml
│           │   └── sqliReport.csv
└── latest.txt
```

6. **Slack integration**

After the testing is finished, a message is sent to the defined channelon slack with a small summary.

7. **Report comparison**

8. **Fetching testing logs**

To gain a deeper insight, we also fetch the logs from the firewall. We do this by copying the audit.log file from modsec-crs container. 


## Post GSoC work

1. The slack integration present in the github action can be integrated with the report comparison feature. Report comparison only prints the output, so it should have the feature to push comparison output to a file or slack message.

2. More test coverage. Currently at 90%.

3. Improve documentation and fix code (bugs) as needed.