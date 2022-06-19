# Project Seaweed

### Assigned Tasks

1. Set modsec-crs container to blocking mode
2. Test all HTTP CVEs from nuclei against CRS and report unblocked ones
3. Test other CVEs like network, ssl ,dns, web socket ...
4. Setup a proper python project
5. Look at Vulcrawler and xlocate to find PoCs.


### Progress

1. CRS is on "blocking mode" by default. Set Paranoia level to 4 on CRS.
1. Added tests, code coverage, nox, poetry & file structure. Todo: linting, typing, documentation, CI/CD
2. Ran HTTP CVE nuclei templates & saved the requests / responses. Wrote a python script to find reponses where `403` code was not found.
3. Analysed xlocate and vulcrawler. 