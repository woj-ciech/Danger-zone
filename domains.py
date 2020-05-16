import sys
import requests
from tld import get_tld
import json
from colors import bcolors
import time
import tools


class Domains:

    def __init__(self, domain):
        self.domain = domain

    def get_tld(self):
        try:
            tld_from_domain = get_tld("https://" + self.domain, as_object=True)
        except:
            print("Unknown domain")
            return False

        req_tld = requests.get("https://raw.githubusercontent.com/mikewesthad/tld-data/master/data/tlds.json")
        json_tld = json.loads(req_tld.content)

        for i in json_tld:
            if i['domain'] == "." + tld_from_domain.extension:
                print("." + tld_from_domain.extension + " is sponsored by " + i['sponsor'])

    def threatcrowd(self, elastic_output):
        output = {}
        req_threatcrowd = requests.get("https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=" + self.domain)
        json_threatcrowd = json.loads(req_threatcrowd.content)
        if json_threatcrowd['response_code'] == "0":
            return False

        print("--------------------Threatcrowd module------------------------")
        votes = json_threatcrowd['votes']
        trust = "non-trusted" if votes < 0 else "trusted" if votes > 0 else "no opinion"
        print("Reputation of " + self.domain + ": " + trust)

        print("[*] Domain was resolved to following IPs: ")
        for i, j in enumerate(json_threatcrowd['resolutions']):
            if i == 3:
                break
            if len(j['ip_address']) > 1:
                print(bcolors.HEADER + j['ip_address'] + bcolors.ENDC)
                output[j["ip_address"]] = j["last_resolved"]

            else:
                del j[
                    'ip_address']  # Threatcrowd gives "-" when there is no IP address. Check if ip_address has 2 chars at least, if not delete it from json_threatcrowd

        # output = {ip:last_resolved}
        if elastic_output:
            tools.elast('threatcrowd', 'domain', json_threatcrowd)

        tools.json_output(self.domain, "/threatcrowd", json_threatcrowd)

        return output
        # return json_threatcrowd

    def whois(self, key, elastic_output):
        print("-------------------WhoIs module---------------------")
        req_whois = requests.get("https://api.whoxy.com/?key=" + key + "&whois=" + self.domain)
        json_whois = json.loads(req_whois.content)
        # #

        output = {self.domain: {}}

        if json_whois['status'] == 0:
            print(bcolors.FAIL + "Whois Retrieval Failed" + bcolors.ENDC)

        try:
            if json_whois['domain_registered'] != 'no':

                print("[*] Domain " + bcolors.HEADER + json_whois[
                    'domain_name'] + bcolors.ENDC + " was registered on " + bcolors.OKGREEN + json_whois[
                          'create_date'] + bcolors.ENDC + " in " + json_whois['domain_registrar']['registrar_name'])
                print("[*] Name servers")

                output[self.domain]['create_date'] = json_whois['create_date']

                for j in json_whois['name_servers']:
                    print(bcolors.OKBLUE + j + bcolors.ENDC)

                output[self.domain]['contact'] = json_whois['registrant_contact']
                output[self.domain]['dns'] = json_whois['name_servers']
                output[self.domain]['domain_name'] = json_whois['domain_name']

                print("[*] Contact: ")

                for k in json_whois['registrant_contact']:
                    print(bcolors.OKBLUE + json_whois['registrant_contact'][k] + bcolors.ENDC)
            else:
                print(bcolors.FAIL + "No match for domain" + self.domain + bcolors.ENDC)

        except KeyError as e:
            print(bcolors.FAIL + "No information found about " + e.message + bcolors.ENDC)

            # create_date, domain_registered, domain_registar, name_servers

        # output = {self.domain : {create_date: xxx, name_servers : [xxxxxx], contact : {x:x}}
        if elastic_output:
            tools.elast('whois', 'domain', json_whois)
        tools.json_output(self.domain, "/whois", json_whois)

        return output
        # return json_whois

    def whois_history(self, key, elastic_output):
        print("-------------------WhoIs history module---------------------")
        req_whois_history = requests.get(
            "http://api.whoxy.com/?key=" + key + "&history=" + self.domain)
        json_whois_history = json.loads(req_whois_history.content)

        output = {}
        help = 0

        if json_whois_history['status'] == 0:
            print("Whois Retrieval Failed")
            return False

        print("[*} Found " + bcolors.OKGREEN + str(
            json_whois_history['total_records_found']) + bcolors.ENDC + " result(s)")

        if json_whois_history['total_records_found'] > 0:

            for c, i in enumerate(json_whois_history['whois_records']):
                try:

                    print("[*] Domain " + bcolors.HEADER + self.domain + bcolors.ENDC + " was registered on " + i[
                        'create_date'] + " in " +  i['domain_registrar']['registrar_name'])
                    # output = {counter: {'create_date': i['create_date'], 'contact': i['registrant_contact'],
                    #                     'dns': i['name_servers']}}
                    output[c] = {}
                    output[c]['create_date'] = i['create_date']
                    output[c]['contact'] = i['registrant_contact']
                    output[c]['dns'] = i['name_servers']
                    output[c]['domain_name'] = i['domain_name']

                    print("[*] Contact: ")
                    for k in i['registrant_contact']:
                        print(bcolors.OKBLUE + i['registrant_contact'][k] + bcolors.ENDC)

                    print("[*] Name servers:")
                    for j in i["name_servers"]:
                        print(bcolors.OKBLUE + j + bcolors.ENDC)

                    help = help + 1

                except KeyError as e:
                    print(bcolors.FAIL + "No information found about " + e.message + bcolors.ENDC)
                    help = help - 1

                print("---")
        else:
            print("No records found")
            return False

        # output = { sdate: :{create_date : xxx, contact : {xxx : xxx}, dns : [xxx]}
        tools.json_output(self.domain, "/whois_history", json_whois_history)

        if elastic_output:
            tools.elast('history', 'domain', json_whois_history)

        return output

        # return json_whois_history

    def virustotal_opinion(self, key):
        print("-------------------VirusTotal module---------------------")
        req_virustotal = requests.get(
            "https://www.virustotal.com/vtapi/v2/url/report?apikey=" + key + "&allinfo=true&resource=" + self.domain)

        if req_virustotal.status_code == 204:
            time.sleep(70)
            req_virustotal = requests.get(
                "https://www.virustotal.com/vtapi/v2/url/report?apikey=" + key + "&allinfo=true&resource=" + self.domain)

        json_virustotal = json.loads(req_virustotal.content)

        if json_virustotal['response_code'] == 0:
            print("[*] No results from VirusTotal")
            return False

        print("[*] Domain " + self.domain + " was last scanned on " + json_virustotal['scan_date'])
        print("[*] Has " + str(json_virustotal['positives']) + " positive results")

        # dorobic skaner

        output = {}
        output[self.domain] = {'scan_date': json_virustotal['scan_date'], 'results': str(json_virustotal['positives'])}

        return output
        # return json_virustotal

    def wayback(self):
        print("----------------------Wayback Machine module------------------------")
        req_wayback = requests.get("http://archive.org/wayback/available?url=" + self.domain)
        json_wayback = json.loads(req_wayback.content)

        if json_wayback['archived_snapshots']:
            print(json_wayback['archived_snapshots']['closest']['url'])
        else:
            print("No results for " + self.domain)

        return json_wayback


    def virustotal(self, key, elastic_output):
        output = {self.domain: []}
        help = 0
        print("----------------VirusTotal module---------------------------")

        req_virustotal = requests.get(
            "https://www.virustotal.com/vtapi/v2/domain/report?apikey=" + key + "&domain=" + self.domain)

        if req_virustotal.status_code == 204:
            print("API limitation, putting into sleep for 70 sec")
            time.sleep(70)
            req_virustotal = requests.get(
                "https://www.virustotal.com/vtapi/v2/domain/report?apikey=" + key + "&domain=" + self.domain)

        if req_virustotal.status_code == 403:
            print("Wrong API key, no more info can be gathered")
            sys.exit()

        json_virustotal = json.loads(req_virustotal.content)

        if json_virustotal['response_code'] != 0:
            print("[*] Domain was resolved to following IPs: ")
            for i in json_virustotal['resolutions']:
                print(bcolors.HEADER + i['ip_address'] + bcolors.ENDC + " on " + bcolors.OKBLUE + i[
                    'last_resolved'] + bcolors.ENDC)
                output[self.domain].append(i['ip_address'])
                help = help + 1
                if help > 2:
                    break
        else:
            print(bcolors.FAIL + "Nothing found" + bcolors.ENDC)

        # output = { self.domain : [xxx.xxx,zzz.zzz,yyy.yyy]
        if elastic_output:
            tools.elast('virustotal', 'domain', json_virustotal)

        tools.json_output(self.domain, "/virustotal", json_virustotal)

        return output
