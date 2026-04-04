import requests

url = "https://standards-oui.ieee.org/"
filename = "resources/oui.txt"

header={
        "accept-language": "tr,en;q=0.9,en-GB;q=0.8,en-US;q=0.7",
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36 Edg/99.0.1150.36'
    }

r = requests.get(url, headers=header)
lines = list(line for line in r.text.split("\n"))

f = open(filename, 'w')

for i in range(0, len(lines)):
    if lines[i].find("hex", 12, 15) != -1:
        e = lines[i].split("\t")
        
        org = e[2].replace('\r', '\n')
        addr = e[0].split()[0].replace('-', ':')

        f.write(addr + '\t' + org)

f.close()