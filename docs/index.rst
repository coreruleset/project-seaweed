Project Seaweed
==============================


Welcome to the documentation of Project Seaweed! Seaweed is a an tool to automate the process of testing CVE(s) against firewalls. It uses CVE(s) from `nuclei templates <https://github.com/projectdiscovery/nuclei-templates>`_ . 

It tests these CVEs using `nuclei <https://github.com/projectdiscovery/nuclei>`_ against a docker setup (Modsec-crs as reverse proxy & httpd as backend server).
After the tests are performed, a report is generated in csv format (or json) along with an analysis file (date, time, crs version, nuclei version, number of CVEs tested etc.).
At the end a slack message is sent to the defined slack channel with a short summary of the test!


.. toctree::
   :hidden:
   :maxdepth: 1   
   
   reference
   installation