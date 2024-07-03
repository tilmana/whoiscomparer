import time
import whois
import ipaddress
import socket

allHosts = []
matches = []
nonmatches = []
invalidHostNames = []
internalIPs = {}
allIPs = []

hostsFile = open("urls.txt", "r")
hostsLines = hostsFile.readlines()
for host in hostsLines:
    host = host.strip("\n")
    host = host.split("://")[1]
    host = host.split(":")[0]
    allHosts.append(host)

ipsFile = open("ips.txt", "r")
ipsLines = ipsFile.readlines()
for ip in ipsLines:
    ip = ip.strip("\n")
    allIPs.append(ip)

allHosts = list(dict.fromkeys(allHosts))
for host in allHosts:
    try:
        ipAddr = socket.gethostbyname(host)
        if ipAddr not in allIPs:
            allHosts.remove(host)
    except Exception as e:
        print("{0} :: {1}".format(e, host))
        invalidHostNames.append(host)
        allHosts.remove(host)
        continue
    if ipaddress.ip_address(ipAddr).is_private:
        internalIPs[host] = ipAddr
        print("Internal IP: {}!".format(host))
        allHosts.remove(host)
        continue
totalHosts = len(allHosts)
count = 0

for host in allHosts:
    time.sleep(3) # without a delay, whois lookups often don't return "org" data from testing
    if host in invalidHostNames or host in internalIPs.keys():
        continue
    count += 1
    print("{0}/{1}".format(count, totalHosts))
    try:
        w1 = whois.whois(host)
        if w1["org"] != None:
            pass
        else:
            raise Exception("Error!")
    except Exception as e:
        print("Error with host: {0}".format(host))
        continue
    if "test123" in w1["org"].lower(): # whois organization data to "match" against
        output = "{0} --- {1}".format(host, w1["org"])
        matches.append(output)
    else:
        output = "{0} --- {1}".format(host, w1["org"])
        nonmatches.append(output)

print("===MATCHES===")

for i in range(len(matches)):
    print(matches[i])

print("===NONMATCHES===")

for i in range(len(nonmatches)):
    print(nonmatches[i])

print("@@@INTERNAL IPS@@@")
for i in internalIPs.keys():
    print(i)

print('-=-INVALID HOSTNAMES-=-')
for i in range(len(invalidHostNames)):
    print(invalidHostNames[i])
