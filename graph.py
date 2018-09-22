import matplotlib.pyplot as plt

import networkx as nx
from elasticsearch import Elasticsearch

# test = collections.defaultdict(dict)
# test['000.000.000.000'] = {'ip' : ['test@test.com', 'pies@pies.pes']}
# test['000.000.000.000'] = {'email': ['xx@x', 'zz@z']}

# test = {'000.000.000.000': {'ip' : ['test@test.com', 'pies@pies.pes']}, {'email': ['xx@x', 'zz@z']}}

test = {'000.000.000.000': {'ip': ['test@test.com', 'pies@pies.pes']}}
test['000.000.000.000'].update({'email': {'xx@x': 'test', 'zzz@z': 'kupa3'}})


# graph = defaultdict(list)
# def addEdge(graph,u,v):
#     graph[u].append(v)
#
# def generate_edges(graph):
#     edges = []
#
#     # for each node in graph
#     for node in graph:
#
#         # for each neighbour node of a single node
#         for neighbour in graph[node]:
#             # if edge exists then append
#             edges.append((node, neighbour))
#     return edges

def graf():
    g = nx.Graph()

    g.add_nodes_from(test.keys())

    for k, v in test.items():
        for i, j in v.items():
            g.add_edges_from([(k, t) for t in j], color='skyblue')

            if isinstance(j, dict):
                for q, w in j.items():
                    g.add_edge(q, w, color='orange')

    #edge_colors = [e[2]['color'] for e in g.edges(data=True)]

    print g.edges

    nx.draw(g, with_labels=True)
    plt.show()


def elast():
    es = Elasticsearch([{'host': 'localhost', 'port': 9200}])
    res = es.index(index='b', doc_type='a', id=2, body=test)
    print res


a = ["1"]
b = ['4', '5', '6']
c = ['7', '8', '9']

G = nx.Graph()

for i in a:
    G.add_node(i)
    for j in b:
        G.add_edge(i, j)
        for k in c:
            G.add_edge(j, k)

    G.add_edge(i, "kupa")

# G.add_nodes_from(b)
nx.draw(G, with_labels=True)
plt.show()
