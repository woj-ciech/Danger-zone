import json
import requests
import time
from colors import bcolors
import tools
import sys

from itertools import islice
# es = Elasticsearch([{'host': 'localhost', 'port': 9200}])


class Ip:

    def __init__(self, ip_address):
        self.ip_address = ip_address

    def geolocation(self, elastic_output):        
        print("-------------Geolocation module---------------------")
        req_geolocation = requests.get("https://extreme-ip-lookup.com/json/" + self.ip_address)
        json_geolocation = json.loads(req_geolocation.content)
        
        try:
            business_name = json_geolocation['businessName']

            print(bcolors.HEADER + self.ip_address + bcolors.ENDC + " belongs to " + bcolors.OKGREEN + business_name if len(
                business_name) > 0 else "No business name for that IP")
            print("It is from " + bcolors.OKGREEN + json_geolocation['country'] + ", " + json_geolocation[
                'city'] + ", " + json_geolocation['region'] + bcolors.ENDC)
        except KeyError:
            print(bcolors.FAIL + "Error" + bcolors.ENDC)

        coordinates = dict(list(islice(json_geolocation.items(), 9, 11)))
        if elastic_output:
            tools.elast('coordinates', 'ip', coordinates)

        tools.json_output(self.ip_address, "/geolocation", json_geolocation)

        return coordinates

    def threatcrowd_ip(self, elastic_output):
        print("----------------ThreatCrowd module---------------------------")
        req_threatcrowd = requests.get("https://www.threatcrowd.org/searchApi/v2/ip/report/?ip=" + self.ip_address)
        json_threatcrowd = json.loads(req_threatcrowd.content)

        try:
            votes = json_threatcrowd['votes']
        except KeyError:
            votes = 0

        output = {self.ip_address: {}}

        if json_threatcrowd['response_code'] == 0:
            print("[*] " + bcolors.FAIL + "No information about " + bcolors.HEADER + self.ip_address + bcolors.ENDC)
            return False
        try:
            newlist = sorted(json_threatcrowd['resolutions'], key = lambda k: k['last_resolved'])
        except KeyError:
            newlist = []
            print("Error")

        print("[*] Newest resolution from ThreatCrowd")
        for i, j in enumerate(reversed(newlist)):
            print(bcolors.HEADER + self.ip_address + bcolors.ENDC + " was resolved to " + bcolors.OKGREEN + j[
                'domain'] + bcolors.ENDC + " on " + bcolors.OKGREEN + j['last_resolved'] + bcolors.ENDC)
            output[self.ip_address]['domain'] = j['domain']
            output[self.ip_address]['last_resolved'] = j['last_resolved']
            if i == 2:
                break

        trust = bcolors.WARNING + "non-trusted" + bcolors.ENDC if votes < 0 else bcolors.OKGREEN + "trusted" + bcolors.ENDC if votes > 0 else "no opinion"
        print("Reputation of " + bcolors.HEADER + self.ip_address + bcolors.ENDC + ": " + trust)

        output[self.ip_address]['trust'] = trust

        # output = {self.ip : {domain:[xxx,xxx], trust: trust}

        if elastic_output:
            tools.elast('threatcrowd_ip', 'domain', json_threatcrowd)
        tools.json_output(self.ip_address, "/threatcrowd", json_threatcrowd)

        return json_threatcrowd

    def virustotal(self, key, elastic_output):
        help = 0
        output = {self.ip_address: {'detected': {}, 'hostname': {}}}
        print("----------------VirusTotal module---------------------------")

        req_virustotal = requests.get(
            "https://www.virustotal.com/vtapi/v2/ip-address/report?apikey=" + key + "&ip=" + self.ip_address)

        if req_virustotal.status_code == 403:
            print("Wrong API key, no more info can be gathered")
            sys.exit()

        if req_virustotal.status_code == 204:
            print("API limit, putting into sleep for 70 sec")
            time.sleep(70)
            req_virustotal = requests.get(
                "https://www.virustotal.com/vtapi/v2/ip-address/report?apikey=" + key + "&ip=" + self.ip_address)

        json_virustotal = json.loads(req_virustotal.content)

        print("[*] Following url(s) was/were hosted on ip " + bcolors.HEADER + self.ip_address + bcolors.ENDC + ' and consider as dangerous: ')

        try:
            for i in json_virustotal['detected_urls']:
                # output[self.ip_address]['detected']['url'] = i['url']
                output[self.ip_address]['detected'][i['url']] = i['scan_date']

                print(i['url'] + " on " + bcolors.OKGREEN + i['scan_date'] + bcolors.ENDC)
                help = help + 1
                if help == 3:
                    break
        except KeyError:
            print("Nothing found")
            return False

        sorted_json_virustotal = sorted(json_virustotal['resolutions'], key=lambda k: k['last_resolved'], reverse=True)
        help = 0
        print("[*] Newest resolution from VirusTotal")
        for i in sorted_json_virustotal:
            if help < 3:

                print(bcolors.HEADER + self.ip_address + bcolors.ENDC + " was resolved to " + bcolors.OKGREEN + i[
                    'hostname'] + bcolors.ENDC + " on " + bcolors.OKGREEN + i['last_resolved'] + bcolors.ENDC)
                output[self.ip_address]['hostname'][i['hostname']] = i['last_resolved']
                help = help + 1
            else:
                break

        # output = {self.ip : { detected {url:scan_date}, hostname : {xxx.xxx.xxx.xxx: xxxx-xx-xx}}

        # output.append([json_virustotal['detected_urls']])

        if elastic_output:
            tools.elast('virustotal_ip', 'ip', json_virustotal)

        tools.json_output(self.ip_address, "/virustotal", sorted_json_virustotal)

        return output
        # return json_virustotal
