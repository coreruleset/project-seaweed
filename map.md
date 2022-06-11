# start

## Trigger mechanism

- [CVE list repo](https://github.com/CVEProject/cvelist)
- [Trickest atom feed](https://github.com/trickest/cve/commits/main.atom)
- [Nuclei templates](https://github.com/projectdiscovery/nuclei-templates) (slow)
- [National Vulnerability database feed](https://nvd.nist.gov/)
- [CVE details RSS feed](https://www.cvedetails.com/vulnerability-feeds-form.php)

## Collect PoC

- [Trickest](https://github.com/trickest/cve)
    - references.txt
    - github.txt
- [Nuclei templates](https://github.com/projectdiscovery/nuclei-templates)
- [NVD project](https://github.com/projectdiscovery/nvd)
- [CVE details](https://www.cvedetails.com/)
- [Exploit DB](www.exploit-db.com)
    - https://www.exploit-db.com/search?cve=2022-29298
## Classify web attacks

- [Nuclei](https://github.com/projectdiscovery/nuclei)
- [Exploit DB](https://www.exploit-db.com/) advanced search
- [CVE details](https://www.cvedetails.com/)
- Keyword lookup (XSS, SSRF, SQLi ...)
- Identify PoC URL as web attacks DB

## Launch PoC

### Setup Environment

- Setup Docker
    - create network (static IP for containers)
    - create volume
- CRS Docker container
    - Container image from Env variable
    - Attach volume (logs)
    - Attach network & static IP
- PoC Docker container
    - Container image from Env variable
    - Attach volume (PoC & it's launch code)
    - Attach network & static IP

### PoC processing

- Plain text payload
    - No / low processing
    - write to Docker volume
    - Write respective launch code

- Code PoC
    - Extract payload (URL / Body)
    - Trigger PoC with CRS container URL as parameter
    - write to Docker volume
    - Write respective launch code
- [Nuclei Action](https://github.com/projectdiscovery/nuclei-action)