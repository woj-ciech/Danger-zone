import json
import requests
import sys

from google import google

import tools
from colors import bcolors


# es = Elasticsearch([{'host': 'localhost', 'port': 9200}])


class Email:

    def __init__(self, email_address):
        self.email_address = email_address
        print bcolors.UNDERLINE + "------------------Trumail module----------------" + bcolors.ENDC
        print "[*] Checking for validity"
        req_trumail = requests.get("https://api.trumail.io/v2/lookups/json?email=" + self.email_address)
        self.json_trumail = json.loads(req_trumail.content)
        try:
            if not self.json_trumail['validFormat']:
                print bcolors.FAIL + "[*] Wrong email format" + bcolors.ENDC
                sys.exit()
            elif not self.json_trumail['deliverable']:
                print "It seems like email address " + bcolors.FAIL + email_address + bcolors.ENDC + " is not deliverable"
            elif not self.json_trumail['hostExists']:
                print bcolors.FAIL + email_address + bcolors.ENDC + " may be not real because host does not exists"
            else:
                print bcolors.OKGREEN + "Email test passed" + bcolors.ENDC
        except KeyError:
            print "No response received from mail server"

    def whoxy(self, key, elastic_output):
        print bcolors.UNDERLINE + "------------Reverse whoxy module-----------------------" + bcolors.ENDC
        req_whoxy = requests.get(
            "https://api.whoxy.com/?key=" + key + "&reverse=whois&email=" + self.email_address)
        json_whoxy = json.loads(req_whoxy.content)

        output = {self.email_address: {}}

        if json_whoxy['status'] == 0:
            print json_whoxy['status_reason']
            sys.exit()

        guard = 0

        # with open('whois_history.json') as f:
        #     data = json.load(f)

        print "Found " + bcolors.OKGREEN + str(json_whoxy[
                                                   'total_results']) + bcolors.ENDC + " results for email: " + bcolors.HEADER + self.email_address + bcolors.ENDC

        if json_whoxy['total_results'] > 0:

            for i in json_whoxy['search_result']:
                print "[*] Domain " + bcolors.HEADER + i[
                    'domain_name'] + bcolors.ENDC + " was registered on " + bcolors.OKGREEN + i[
                          'create_date'] + bcolors.ENDC
                output[self.email_address][guard] = {i['domain_name']: {}}
                output[self.email_address][guard]['domain_name'] = i['domain_name']
                output[self.email_address][guard]['create_date'] = i['create_date']

                try:
                    output[self.email_address][guard]['dns'] = i['name_servers']
                    output[self.email_address][guard]['contact'] = i['registrant_contact']
                    # output[self.email_address][i['domain_name']]['create_date']= i['create_date']
                    # output[self.email_address][i['domain_name']]['contact'] = i['registrant_contact']
                    # output[self.email_address][i['domain_name']]['dns'] = i['name_servers']
                    print "[*] Name servers:"
                    for j in i['name_servers']:
                        print bcolors.OKBLUE + j + bcolors.ENDC

                    print "[*] Contact: "
                    for k in i['registrant_contact']:
                        print bcolors.OKBLUE + i['registrant_contact'][k] + bcolors.ENDC

                except KeyError as e:
                    guard = guard - 1
                    print e
                    print "No more info"

                guard = guard + 1

                if guard == 3:  # first three if there are 4000
                    break

        else:
            print "No records found"
            # domain_name : create_date : xxx, dn

            # output = { self.email :{domain : xxx, create_date : xxx, contact : {xxx : xxx}, dns : [xxx]}

        if elastic_output:
            tools.elast('reverse_whois', 'email', json_whoxy)
        tools.json_output(self.email_address, "/reverse_whois", json_whoxy)

        return output
        # return json_whoxy

    def haveibeenpwned(self):
        print bcolors.UNDERLINE + "-------------------HaveIBeenPwned module---------------------" + bcolors.ENDC
        user_agent = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36"}
        req_haveibeenpwned = requests.get("https://haveibeenpwned.com/api/v2/breachedaccount/" + self.email_address,
                                          headers=user_agent)
        if req_haveibeenpwned.status_code != 200:
            if req_haveibeenpwned.status_code == 404:
                print "account not pwned"
                return False
            print "Connection error " + str(req_haveibeenpwned.status_code) + " " + req_haveibeenpwned.text
            return False

        json_haveibeenpwned = json.loads(req_haveibeenpwned.content)
        domains = []
        for i in json_haveibeenpwned:
            domains.append(i['Domain'])

        if len(domains) > 0:
            for i in domains:
                print bcolors.OKGREEN + i + bcolors.ENDC
        else:
            print "No results"

        return domains

    def check_username(self):
        print bcolors.UNDERLINE + "-------------------Checking usernames---------------------" + bcolors.ENDC
        username = self.email_address.split('@')[0]
        print "[*] https://username-availability.herokuapp.com/"
        print "[*] Looking for username " + bcolors.OKGREEN + username + bcolors.ENDC

        social_sites = ["asciinema", "behance", "deviantart", "facebook", "twitter", "instagram", "medium", "gitlab",
                        "github", "openhub", "pinterest", "soundcloud", "tumblr"]

        possible_accounts = []
        for i in social_sites:
            social_sites_req = requests.get("https://username-availability.herokuapp.com/check/" + i + "/" + username)
            social_sites_json = json.loads(social_sites_req.content)
            if social_sites_json['usable']:
                print social_sites_json['url']
                possible_accounts.append(social_sites_json['url'])

        return possible_accounts

    def google(self):
        print bcolors.UNDERLINE + "------------Google module---------------------" + bcolors.ENDC
        print "First Page"
        search_results = google.search("\"" + self.email_address + "\"", 1)
        results = {}
        others = []
        for result in search_results:
            print bcolors.OKGREEN + result.name + bcolors.ENDC
            print bcolors.FAIL + result.description + bcolors.ENDC
            print result.link
            others.append(result.name)
            others.append(result.description)
            others.append(result.link)
            results = {result.link: others}
            others = []

        return results
