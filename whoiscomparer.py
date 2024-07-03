import time # added 2 second delays after each whois lookup because for some domains it seems to not return "org" data if performed quickly?
import whois
import requests
import ipaddress
import socket

requests.packages.urllib3.disable_warnings()

ipMode = input("Remove hosts that do not resolve to IPs in \"ips.txt\"? (Y/N): ").lower()

allHosts = []
matches = []
nonmatches = []
invalidHostNames = []
internalIPs = {}
allIPs = []
allHosts2 = []

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Encoding": "gzip, deflate, br"
}

hostsFile = open("whoisurls.txt", "r")
hostsLines = hostsFile.readlines()
for host in hostsLines:
    host = host.strip("\n")
    allHosts.append(host)

ipsFile = open("ips.txt", "r")
ipsLines = ipsFile.readlines()
for ip in ipsLines:
    ip = ip.strip("\n")
    allIPs.append(ip)

for host in allHosts:
    if "://" in host:
        host = host.split("://")[1]
    if ":" in host:
        host = host.split(":")[0]
    if "/" in host:
        host = host.strip("/")
    allHosts2.append(host)

oldHosts = allHosts.copy()
allHosts = list(dict.fromkeys(allHosts2.copy()))
allIPs = list(dict.fromkeys(allIPs.copy()))

for host in allHosts:
    try:
        ipAddr = socket.gethostbyname(host)
        print(ipAddr)
        if ipMode == "y":
            if ipAddr not in allIPs:
                allHosts2.remove(host)
    except Exception as e:
        print("{0} :: {1}".format(e, host))
        invalidHostNames.append(host)
        allHosts2.remove(host)
        continue
    if ipaddress.ip_address(ipAddr).is_private:
        internalIPs[host] = ipAddr
        print("Internal IP: {}!".format(host))
        allHosts2.remove(host)

totalHosts = len(allHosts2)
count = 0

for host in allHosts2:
    if host in invalidHostNames or host in internalIPs.keys():
        continue
    count += 1
    print("{0}/{1}".format(count, totalHosts))
    error = False
    try:
        r1 = requests.get(url="http://" + host, timeout=8, allow_redirects=True, verify=False, headers=headers)
    except Exception as e:
        try:
            r1 = requests.get(url="https://" + host, timeout=8, allow_redirects=True, verify=False, headers=headers)
        except Exception as e:
            error = True
    if error == True:
        try:
            w1 = whois.whois(host)
            time.sleep(2)
            if w1["org"] != None:
                pass
            else:
                raise Exception("Error!")
        except Exception as e:
            try:
                host = '.'.join(host.split(".")[-2:])
                w1 = whois.whois(host)
                time.sleep(2)
                if w1["org"] != None:
                    pass
                else:
                    raise Exception("Error!")
            except Exception as e:
                print("Error with host: {0}".format(host))
                continue
        if "test123" in w1["org"].lower():
            output = "{0} --- {1}".format(host, w1["org"])
            matches.append(output)
        else:
            output = "{0} --- {1}".format(host, w1["org"])
            nonmatches.append(output)
        continue
    if len(r1.history) > 0:
        host1 = r1.history[0].url.split("://")[1]
        host2 = r1.history[-1].url.split("://")[1]
        if ":" in host1:
            host1 = host1.split(":")[0]
        if "?" in host1:
            host1 = host1.split("?")[0]
        if "/" in host1:
            host1 = host1.split("/")[0]
        if "\\" in host1:
            host1 = host1.split("\\")[0]
        if ":" in host2:
            host2 = host2.split(":")[0]
        if "?" in host2:
            host2 = host2.split("?")[0]
        if "/" in host2:
            host2 = host2.split("/")[0]
        if "\\" in host2:
            host2 = host2.split("\\")[0]
        try:
            w1 = whois.whois(host1)
            time.sleep(2)
            w2 = whois.whois(host2)
            time.sleep(2)
            w3 = len(r1.history)
            if w1["org"] != None and w2["org"] != None:
                pass
            else:
                raise Exception("Error!")
        except Exception as e:
            try:
                host1 = '.'.join(host1.split(".")[-2:])
                host2 = '.'.join(host2.split(".")[-2:])
                w1 = whois.whois(host1)
                time.sleep(2)
                w2 = whois.whois(host2)
                time.sleep(2)
                w3 = len(r1.history)
                if w1["org"] != None and w2["org"] != None:
                    pass
                else:
                    raise Exception("Error!")
            except Exception as e:
                print("Error with host: {0}".format(host))
                continue
        if "test123" in w1["org"].lower():
            output = "{0} --->> {1} --- {2} (R: {3})".format(host1, host2, w2["org"], w3)
            matches.append(output)
        else:
            output = "{0} --->> {1} --- {2} (R: {3})".format(host1, host2, w2["org"], w3)
            nonmatches.append(output)
    else:
        host1 = r1.url.split("://")[1]
        if ":" in host1:
            host1 = host1.split(":")[0]
        if "?" in host1:
            host1 = host1.split("?")[0]
        if "/" in host1:
            host1 = host1.split("/")[0]
        if "\\" in host1:
            host1 = host1.split("\\")[0]
        try:
            w1 = whois.whois(host1)
            time.sleep(2)
            if w1["org"] != None:
                pass
            else:
                raise Exception("Error!")
        except Exception as e:
            try:
                host1 = '.'.join(host1.split(".")[-2:])
                w1 = whois.whois(host1)
                time.sleep(2)
                if w1["org"] != None:
                    pass
                else:
                    raise Exception("Error!")
            except Exception as e:
                print("Error with host: {0}".format(host))
                continue
        if "test123" in w1["org"].lower():
            output = "{0} --- {1}".format(host1, w1["org"])
            matches.append(output)
        else:
            output = "{0} --- {1}".format(host1, w1["org"])
            nonmatches.append(output)

print("===ORIGINALS===")

combinedHosts = matches + nonmatches
for host in combinedHosts:
    if " " in host:
        host = host.split(" ")[0]
    for host2 in oldHosts:
        if host in host2:
            print(host2)
            continue

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
