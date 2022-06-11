import bs4
import requests
import re

#url="https://huntr.dev/bounties/df46e285-1b7f-403c-8f6c-8819e42deb80/"
url="https://www.exploit-db.com/exploits/50950"

headers={"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:101.0) Gecko/20100101 Firefox/101.0"}
response=requests.get(url=url,headers=headers)
print(response.status_code)
soup=bs4.BeautifulSoup(response.text,features="html.parser")

PoC=str(soup.find('code').text)

print(PoC,end="\n\n\n")

print(re.findall("https?://.*",PoC))