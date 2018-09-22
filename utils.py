import domains
import emails
import ip
import tools

domain_list = []
email_list = []

conf = tools.parse_config()


class Utils:

    def get_email_from_domain(self, domain_name, elastic_output):
        global email_list
        domain3 = domains.Domains(domain_name)
        domain3.get_tld()
        domain3.wayback()
        whois_history = domain3.whois_history(conf['keys']['whoxy'], elastic_output)
        whois = domain3.whois(conf['keys']['whoxy'], elastic_output)

        new_emails = []

        # KeyErrors are here because sometimes contact does not contain email address. API does not give key in that case.
        try:
            if whois:
                if whois[domain_name]['contact']['email_address'] not in email_list:
                    email_list.append(whois[domain_name]['contact']['email_address'])
                    new_emails.append(whois[domain_name]['contact']['email_address'])
        except KeyError:
            pass

        try:
            if whois_history:
                for j in whois_history:
                    if whois_history[j]['contact']['email_address'] not in email_list:
                        email_list.append(whois_history[j]['contact']['email_address'])
                        new_emails.append(whois_history[j]['contact']['email_address'])
        except KeyError:
            pass
        return new_emails

    def get_domain_from_email(self, email_address, elastic_output):
        global domain_list
        email1 = emails.Email(email_address)
        email1.google()
        email1.haveibeenpwned()
        email1.check_username()
        whoxy = email1.whoxy(conf['keys']['whoxy'], elastic_output)

        new_domains = []

        if whoxy[email_address]:
            for i, j in whoxy[email_address].items():
                new_domains.append(j['domain_name'])
                domain_list.append([j['domain_name']])

        return new_domains

    def get_ip_from_domain(self, domain_name, elastic_output):
        domain2 = domains.Domains(domain_name)
        # domain2.get_tld()
        # domain2.wayback()
        # domain2.virustotal()
        domain2.threatcrowd(elastic_output)
        domain_virustotal = domain2.virustotal(conf['keys']['virustotal'], elastic_output)
        domain2.whois_history(conf['keys']['whoxy'], elastic_output)

        new_ip = []

        if domain_virustotal:
            if len(domain_virustotal) > 0:
                for i in domain_virustotal[domain_name]:
                    new_ip.append(i)
        else:
            print "Nothing found"

        return new_ip

    def get_domain_from_ip(self, ip_address, elastic_output):
        global domain_list
        counter = 0
        ip1 = ip.Ip(ip_address)
        ip1.geolocation(elastic_output)
        ip1.threatcrowd_ip(elastic_output)
        ip_virustotal = ip1.virustotal(conf['keys']['virustotal'], elastic_output)

        new_domains = []
        if ip_virustotal:
            for j in ip_virustotal[ip_address]['hostname']:
                if counter <= 3:
                    if j not in domain_list:
                        counter = counter + 1
                        domain_list.append(j)
                        new_domains.append(j)

        return new_domains
