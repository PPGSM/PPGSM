import networkx as nx
import matplotlib.pyplot as plt
from networkx.drawing.nx_agraph import graphviz_layout
import random
import sys

#def erdos_renyi(G,p):
#    sys.stdout = open('simpleGraph.txt','w')
#    for i in G.nodes():
#        for j in G.nodes():
#            if i != j:
#                r = random.random()
#                if r <= p:
#                    G.add_edge(i,j)
#                    ne = [(i,j)]
#                    print("1"),
#                    #display_graph(G, '', ne)
#                else:
#                    ne = []
#                    #display_graph(G, '', ne)
#                    print("0"),
#                    continue
#            else:
#                print("1"),
#        print("")

def main():
    n = int(input('Enter the value of n'))
    m = int(input('Enter the value of m'))
    p = float(input('Enter the value of p'))
    q = float(input('Enter the value of q'))

    for i in range(1):
#        title = "gnp_random_graph_density50-" + str(i) + ".txt"
#        G = nx.gnp_random_graph(n,p)

#        title = "erdos_renyi_graph-" + str(i) +".txt"
#        G = nx.erdos_renyi_graph(n,p)

        title = "barabasiGraphLarge"
        G = nx.barabasi_albert_graph(n,m)

#        title = "power_law_cluster-" + str(i) + ".txt"
#        G = nx.powerlaw_cluster_graph(n,m,p)

        s = G.number_of_nodes()

        adjMat = [[0 for x in range(s)] for y in range(s)]
        for a in range(s):
            for b in list(G.neighbors(a)):
                    adjMat[a][b]=1


        sys.stdout = open(title, 'w')
        for a in range(s):
            for b in range(s):
                print(str(adjMat[a][b])+' ',end='')
            print('')

main()
