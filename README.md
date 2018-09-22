# Danger zone
![Danger_zone](https://media1.giphy.com/media/hWoDtMnsUYdVu/giphy.gif)
## Info
Correlate data between domains, ips and email addresses, present it as a graph and store everything into Elasticsearch and JSON files.\
Background story --> https://medium.com/@woj_ciech/osint-tool-for-visualizing-relationships-between-domains-ips-and-email-addresses-94377aa1f20a

## Cases
* Based on given email, check for associate domains and then check these domains for other emails and IPs.
* For domains check for IP and Emails and next look for associated domains.
* Extract domain from IP, check domain for other IPs and email.

## Modules
- Email:
	- Trumail - Validation email address (https://trumail.io/)
	- Whoxy - Reverse Whois service (https://whoxy.com/) KEY NEEDED
	- haveIbeenPwned - Dumps (https://haveibeenpwned.com/)
	- Username check - Check username, based on email address, across social media sites (https://username-availability.herokuapp.com/)
	- Google - Query Google
- IP:
	- Geolocation - Geolocate IP (https://extreme-ip-lookup.com/)
	- Threatcrowd - Information about IP (https://github.com/AlienVault-OTX/ApiV2)
	- VirusTotal - Information about IP (https://www.virustotal.com/) Key needed
- Domain:
	- TLD - Get sponsor of particular Top Level Domain (https://raw.githubusercontent.com/mikewesthad/tld-data/master/data/tlds.json)
	- Threatcrowd - Information about domain (https://github.com/AlienVault-OTX/ApiV2)
	- Whoxy - Whois service (https://whoxy.com/) 
	- Whois history - Historical data about domain (https://whoxy.com/)
	- Wayback Machine - Archive version of website (http://archive.org/)
	- VirusTotal - Information about domain (https://www.virustotal.com/)
	
## Setup & Configuration:
```bash
git clone
pip install -r requirements.txt
```
```
pip install google
```

For Elasticsearch setup go here https://www.elastic.co/guide/en/elasticsearch/reference/current/_installation.html

For Kibana setup go here https://www.elastic.co/guide/en/kibana/6.4/install.html

__Edit settings.json file and put there your keys and ElasticSearch info__
```json
{
  "keys":{
    "whoxy": "xxx",
    "virustotal": "xxx"
  },
  "elastic":{
    "host":"127.0.0.1",
    "port":9200
  }
}
```

### Usage
```
python danger-zone.py -h
usage: dangerzone.py [-h] [--email EMAIL] [--address ADDRESS] [--domain DOMAIN]
               [--elasticsearch]

Correlate data between domains, ips and email addresses and present it as a
graph.

optional arguments:
  -h, --help         show this help message and exit
  --email EMAIL      Email address
  --address ADDRESS  IP address
  --domain DOMAIN    Domain name
  --elasticsearch    Elasticsearch output
```

**Example domain check**
```
python danger-zone.py --domain example.net --elastic
Succesfully connected to ElasticSearch
----------------VirusTotal module---------------------------
[*] Domain was resolved to following IPs: 
xxx.xxx.xxx.xxx on 2017-02-20 00:00:00
[*] Saving output to Elasticsearch
-------------------WhoIs history module---------------------
[*} Found 1 result(s)
[*] Domain example.net was registered on 2017-02-15 in GoDaddy.com, LLC
[*] Contact: 
[REDACTED]
[*] Name servers:
ns47.domaincontrol.com
ns48.domaincontrol.com
---
[*] Saving output to Elasticsearch
.net is sponsored by VeriSign Global Registry Services
[...]
--------------------Threatcrowd module------------------------
Reputation of 0downcarleasedeals.com: no opinion
[*] Domain was resolved to following IPs: 
xxx.xxx.xxx.xxx
xxx.xxx.xxx.xxx
xxx.xxx.xxx.xxx
[*] Saving output to Elasticsearch
----------------VirusTotal module---------------------------
API limitation, putting into sleep for 70 sec
[*] Domain was resolved to following IPs: 
xxx.xxx.xxx.xxx on 2017-09-28 00:00:00
xxx.xxx.xxx.xxx on 2018-08-22 13:57:06
xxx.xxx.xxx.xxx on 2018-09-21 00:28:27
[*] Saving output to Elasticsearch
-------------------WhoIs history module---------------------
[*} Found 1 result(s)
[*] Domain example2.com was registered on 2017-01-24 in GoDaddy.com, LLC
[*] Contact: 
[REDACTED]
[*] Name servers:
ns47.domaincontrol.com
ns48.domaincontrol.com
---
[*] Saving output to Elasticsearch
[*] Saving graph to graph/20180920-185210-example.net.png
Press Enter to quit...
```

## Outputs
### Graph:
Generated graph which started from fximperium[.]net 
![](https://i.imgur.com/sV5yHRZ.png)

### Console
Report generated to console contains more information than saved files.\
Additional information are Google results, username check and HaveIBeenPwned module.\
The most important things are colored in console, which lets you better remember and associate findings.
![](https://i.imgur.com/GIr3whY.png)

### Kibana
It creates index with name of each module contains specific information
![](https://i.imgur.com/XKvpIsv.png)


### JSON
The following structure is created.\
![](https://i.imgur.com/YGHNfFW.png)

## Limitations
I tried to find as many free of charge services I could but nothing good is for free. Luckily, you need to create only two account to use this tool. First is VirusTotal, which is totally free but allows you to make only 4 request per minute.\
Whoxy service provides you free credits at the beginning and it's enough to test it and gather all of the useful info.\
It goes only 2-3 level down checking only 3 newest findings, the reason behind that is graph would be unreadable with lots of connections, but full information is saved into JSON files and/or ElasticSearch.

## Golden rule
### Don't jump to conclusions too fast.
