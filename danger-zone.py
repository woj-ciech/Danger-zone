import argparse
import sys
from colors import bcolors
import networkx as nx
import utils
import tools

util = utils.Utils()

parser = argparse.ArgumentParser(
    description='Correlate data between domains, ips and email addresses and present it as a graph. ')

parser.add_argument("--email", help="Email address",
                    default="")
parser.add_argument("--address", help="IP address")
parser.add_argument("--domain", help="Domain name")
parser.add_argument('--elasticsearch', help='Elasticsearch output', action='store_true')

args = parser.parse_args()

elastic = args.elasticsearch
email = args.email
address = args.address
domain = args.domain

elastic_output = False

if elastic:
    tools.test_connection()
    elastic_output = True
else:
    tools.parse_config()

G = nx.Graph()

if email:
    ip_help = []
    email_help = []

    G.add_node(email)
    domains_from_email = util.get_domain_from_email(email, elastic_output)

    if len(domains_from_email) > 0:
        print "Found domain: "
        for i_domain in domains_from_email:
            print bcolors.OKGREEN + i_domain + bcolors.ENDC
            G.add_edge(email, i_domain)

        answer1 = raw_input("Do you want to check domains? [y/n] ")
        if answer1 == "y":
            for j_domain in domains_from_email:
                tools.finding(j_domain)
                ips_from_domain = util.get_ip_from_domain(j_domain, elastic_output)
                email1_from_domain = util.get_email_from_domain(j_domain, elastic_output)

                for i_email in email1_from_domain:
                    email_help.append(i_email)
                    G.add_edge(j_domain, i_email, color='green')

                for i_ip in ips_from_domain:
                    ip_help.append(i_ip)
                    G.add_edge(j_domain, i_ip, color='yellow')
        else:
            print "[*] Bye "
            tools.save_graph(G, email)
            sys.exit()
    else:
        print "No domain found"
        sys.exit()

    if len(ip_help) > 0:
        print "Found following IPs "
        for j_ip in ip_help:
            print bcolors.OKGREEN + j_ip + bcolors.ENDC

        answer2 = raw_input("Do you want to check IP(s)? [y/n] ")
        if answer2 == "y":
            for k_ip in ip_help:
                tools.finding(k_ip)
                domain_from_ip = util.get_domain_from_ip(k_ip, elastic_output)
                for k_domain in domain_from_ip:
                    G.add_edge(k_ip, k_domain)
                    print k_domain

        else:
            print "[*] Bye"
            tools.save_graph(G, email)
            sys.exit()

    else:
        tools.save_graph(G, email)
        print "No IP was found"
        sys.exit()

    tools.save_graph(G, email)

elif address:
    emails_help = []
    domains_help = []
    G.add_node(address)
    ip_help = []

    domain_from_ip = util.get_domain_from_ip(address, elastic_output)

    print "Found domain:"
    for i_domain in domain_from_ip:
        G.add_edge(address, i_domain)
        print bcolors.OKGREEN + i_domain + bcolors.ENDC

    if len(domain_from_ip) > 0:
        answer3 = raw_input("Do you want to check domain(s)? [y/n] ")
        if answer3 == "y":
            for j_domain in domain_from_ip:
                tools.finding(j_domain)
                email_from_domain = util.get_email_from_domain(j_domain, elastic_output)
                ip_from_domain = util.get_ip_from_domain(j_domain, elastic_output)
                G.add_edge(address, j_domain)

                for i_ip in ip_from_domain:
                    G.add_edge(j_domain, i_ip)
                    ip_help.append(i_ip)

                for i_email in email_from_domain:
                    G.add_edge(j_domain, i_email)
                    emails_help.append(i_email)
        else:
            for j_domain in domain_from_ip:
                G.add_edge(address, j_domain)

                tools.save_graph(G, address)

    else:
        print "No domain found"
        sys.exit()

    if len(emails_help) > 0:
        print "Found emails:"
        for j_email in emails_help:
            print j_email

        answer4 = raw_input("Do you want to check email(s) [y/n] ")
        if answer4 == 'y':
            for k_email in emails_help:
                tools.finding(k_email)
                domains_from_email1 = util.get_domain_from_email(k_email, elastic_output)

                for k_domain in domains_from_email1:
                    domains_help.append(k_domain)
                    G.add_edge(k_email, k_domain)
        else:
            tools.save_graph(G, address)
            sys.exit()
    else:
        print "No email found"
        tools.save_graph(G, address)
        sys.exit()

    if len(domains_help) > 0:
        print "Found domains:"

        for l_domain in domains_help:
            tools.finding(l_domain)
            email_from_domain1 = util.get_email_from_domain(l_domain, elastic_output)

            for l_email in email_from_domain1:
                tools.finding(l_email)
                G.add_edge(l_domain, l_email)
    else:
        tools.save_graph(G, address)
        print "No domain found"
        sys.exit()

    tools.save_graph(G, address)

elif domain:
    domains_help = []
    counter = 0
    answer7 = 'x'

    G.add_node(domain)

    ip_tmp = util.get_ip_from_domain(domain, elastic_output)
    email_tmp = util.get_email_from_domain(domain, elastic_output)

    print "[*] Found email"
    for i_email in email_tmp:
        G.add_edge(domain, i_email)
        print i_email

    print "[*] Found IP: "
    for i_ip in ip_tmp:
        print bcolors.HEADER + i_ip + bcolors.ENDC
        G.add_edge(domain, i_ip)

    print "[*] Going deeper..."
    for j_email in email_tmp:
        tools.finding(j_email)
        domains_from_email1 = util.get_domain_from_email(j_email, elastic_output)

        for i_domain in domains_from_email1:
            tools.finding(i_domain)
            G.add_edge(j_email, i_domain)
            domains_help.append(i_domain)
            ip_from_domains2 = util.get_ip_from_domain(i_domain, elastic_output)
            email_from_domain2 = util.get_email_from_domain(i_domain, elastic_output)

            for j_ip in ip_from_domains2:
                G.add_edge(i_domain, j_ip)

            for k_email in email_from_domain2:
                G.add_edge(i_domain, k_email)
                tools.finding(k_email)
                domain_from_email = util.get_domain_from_email(k_email, elastic_output)

                for m in domain_from_email:
                    G.add_edge(k_email, m)

    for k_ip in ip_tmp:
        tools.finding(k_ip)
        domains_from_ip = util.get_domain_from_ip(k_ip, elastic_output)

        for k_domain in domains_from_ip:
            G.add_edge(k_ip, k_domain)
            tools.finding(k_domain)
            ip_from_domain3 = util.get_ip_from_domain(k_domain, elastic_output)

            for l_ip in ip_from_domain3:
                G.add_edge(k_domain, l_ip)

        tools.save_graph(G, domain)
