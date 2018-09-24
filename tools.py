from __future__ import print_function
import json
import os
from elasticsearch import Elasticsearch
import time
import matplotlib.pyplot as plt
import networkx as nx
import sys
from colors import bcolors

try:
    raw_input          # Python 2
except NameError:
    raw_input = input  # Python 3


def parse_config():
    conf_file = 'settings.json'
    try:
        with open(conf_file, 'r') as read_conf:
            conf = json.load(read_conf)
    except Exception as e:
        print("Unable to parse config file: {0}".format(e))
        sys.exit()

    return conf


def test_connection():
    config = parse_config()
    try:
        es = Elasticsearch(host=config['elastic']['host'], port=config['elastic']['port'])
        print("Succesfully connected to ElasticSearch")
        return es
    except:
        print('Unable to connect to Elasticsearch. \nCheck your connection and settings.json file')
        sys.exit()


def elast(index, doc_type, body):
    config = parse_config()
    es = Elasticsearch(host=config['elastic']['host'], port=config['elastic']['port'])
    # es = Elasticsearch([{'host': 'localhost', 'port': 9200}])
    ids = []
    print("[*] Saving output to Elasticsearch")
    try:
        resp = es.search(index=index)
        for i in resp['hits']['hits']:
            int_id = int(i['_id'])
            ids.append(int_id)

        last_id = max(ids)

        es.index(index=index, doc_type=doc_type, id=last_id + 1, body=body)
    except Exception as e:
        try:
            es.index(index=index, doc_type=doc_type, id=1, body=body)
        except Exception as e:
            pass


def json_output(name, filename, data):
    directory = "output/" + name + "/"
    if not os.path.exists(directory):
        os.makedirs(directory)
    with open(directory + filename + ".json", 'w') as outfile:
        json.dump(data, outfile, indent=4, sort_keys=False)


def finding(finding):
    print(bcolors.OKGREEN + "---------------------------------------------------------" + bcolors.ENDC + finding + bcolors.OKGREEN + "---------------------------------------------------------" + bcolors.ENDC)


def save_graph(G, name):
    directory = "graph/"
    if not os.path.exists(directory):
        os.makedirs(directory)
    # edges = G.edges
    # colors = [G[u][v]['color'] for u, v in edges]
    nx.draw(G, with_labels=True)  # ,edge_colors=colors)
    # plt.figure(figsize=(10,10))

    timestr = time.strftime("%Y%m%d-%H%M%S")
    print("[*] Saving graph to graph/" + timestr + '-' + name + ".png")
    plt.savefig(directory + timestr + '-' + name + ".png")
    plt.show()
    raw_input("Press Enter to quit...")
    sys.exit()
    # nx.draw(G, with_labels=True)
    # plt.show()
