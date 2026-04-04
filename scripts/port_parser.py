import requests

url = "https://raw.githubusercontent.com/nmap/nmap/refs/heads/master/nmap-services"
filename = "resources/ports.txt"

header = {
        "accept-language": "tr,en;q=0.9,en-GB;q=0.8,en-US;q=0.7",
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36 Edg/99.0.1150.36'
    }

r = requests.get(url, headers=header)
lines = list(line for line in r.text.split("\n"))

f = open(filename, 'w')

for i in range(0, len(lines) - 1):
    if lines[i][0] == '#':
        continue

    e = lines[i].split()

    if e[0] == "unknown":
        continue
    
    service_name = e[0]
    port_num, prot = e[1].split("/")

    f.write(service_name + ' ' + port_num + ' ' + prot + '\n')    

f.close()