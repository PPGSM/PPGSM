from scipy import mean
import numpy as np
import networkx as nx
import random

def extract_graph_from_adjacent_matrix(file):
    #graph creation
    G = nx.DiGraph()
    #input file open
    input = open(file, 'r')
    topology = []
    #reading topology from file
    for lines in input:
        edges = [int(x) for x in lines.split(' ')]
        topology.append(edges);
    node_number = len(topology);
    for index in range(0, node_number):
        G.add_node(index);
    for index1 in range(0, node_number):
        for index2 in range(0, node_number):
                if(topology[index1][index2] == 1):
                    G.add_edge(index1, index2)
    input.close()
    return G

def randomly_added(G):
    #average degree
    D = list(map(lambda x : x[1], list(G.degree(G.nodes))))
    D_mean = int(np.mean(D))
    #shuffle node list
    shuffled_node_list = list(G.nodes())
    random.shuffle(shuffled_node_list)
    """ 
    ##test - check node list shuffled
    for i in shuffled_node_list:
        print(i, end=',');
    print()
    """
    #add dummy node
    G.add_node(G.number_of_nodes())
    dummyNode = G.number_of_nodes() - 1
    edge_to_add = D_mean
    for idx in range(0,edge_to_add):
        """
        ##test - check added edge
        print(idx, end=': ')
        print(shuffled_node_list[idx],end=',')
        print(dummyNode)
        """
        G.add_edge(shuffled_node_list[idx],dummyNode)
        G.add_edge(dummyNode,shuffled_node_list[idx])

def randomly_added(G,node_to_add):
    #average degree
    D = list(map(lambda x : x[1], list(G.degree(G.nodes))))
    D_mean = int(np.mean(D))
    #shuffle node list
    shuffled_node_list = list(G.nodes())
    
    """ 
    ##test - check node list shuffled
    for i in shuffled_node_list:
        print(i, end=',');
    print()
    """
    #add dummy node
    for dummy in range(0, node_to_add):
        random.shuffle(shuffled_node_list)
        G.add_node(G.number_of_nodes())
        dummyNode = G.number_of_nodes() - 1
        edge_to_add = D_mean
        for idx in range(0,edge_to_add):
            """
            ##test - check added edge
            print(idx, end=': ')
            print(shuffled_node_list[idx],end=',')
            print(dummyNode)
            """
            G.add_edge(shuffled_node_list[idx],dummyNode)
            G.add_edge(dummyNode,shuffled_node_list[idx])

def dummy_edge_low_BC(G):
    #average degree
    D = list(map(lambda x : x[1], list(G.degree(G.nodes))))
    edge_to_add = int(np.mean(D))
    #calculate betweenness centrality.
    B = nx.betweenness_centrality(G)
    #calculate sorted betweenness centrality list.
    B_sort = sorted(B.items(),key=(lambda x:x[1]))
    """
    ##test - check betweenness centrality sorted
    for i in B_sort:
        print(i[0], end=', ');
    print()
    """
    #add dummy node
    G.add_node(G.number_of_nodes())
    dummyNode = G.number_of_nodes()-1
    #add dummy edge
    for idx in range(0, edge_to_add):
        """
        ## test - check edge added
        print(ind, end = ': ' )
        print(B_sort[ind][0], end=', ')
        print(dummyNode)
        """
        G.add_edge(B_sort[idx][0],dummyNode)
        G.add_edge(dummyNode,B_sort[idx][0])

def dummy_edge_low_BC_weighted_choice(G,node_to_add, destination_node):
    #average degree
    D = list(map(lambda x : x[1], list(G.degree(G.nodes))))
    edge_to_add = int(np.mean(D))
    #calculate betweenness centrality.
    DegreeDict = {};
    DummyDegreeDict = {};
    #calculate betweenness centrality.
    Bdict = nx.betweenness_centrality_subset(G,sources=set(G.nodes()),targets=set({destination_node}))
    B = []
    for key in Bdict.keys():
        B.append((key,Bdict[key]))
        DegreeDict[key] = G.degree[key];
        DummyDegreeDict[key] = 0;
    #Weighted k-sampling
    for dummy in range(0, node_to_add):
        Bdg = []
        for element in B:
            m = DegreeDict[element[0]]
            n = DummyDegreeDict[element[0]]
            Bdg.append((element[0],element[1]))
        target_nodes = random.choices(list(map(lambda x : x[0], Bdg)),weights=list(map(lambda x : 1-x[1], Bdg)),k=edge_to_add)
        #add dummy node
        G.add_node(G.number_of_nodes())
        dummyNode = G.number_of_nodes()-1
        #add dummy edge
        for target in target_nodes:
            G.add_edge(target,dummyNode);
            G.add_edge(dummyNode,target);
            DummyDegreeDict[target]+=1;

def dummy_edge_high_BC(G):
    #average degree
    D = list(map(lambda x : x[1], list(G.degree(G.nodes))))
    edge_to_add = int(np.mean(D))
    #calculate betweenness centrality.
    B = nx.betweenness_centrality(G)
    #calculate sorted betweenness centrality list.
    B_sort = list(reversed(sorted(B.items(),key=(lambda x:x[1]))))
    """
    ##test - check betweenness centrality sorted
    for i in B_sort:
        print(i, end=', ');
    print()
    """
    #add dummy node
    G.add_node(G.number_of_nodes())
    dummyNode = G.number_of_nodes()-1
    #add dummy edge
    for idx in range(0, edge_to_add):
        """ 
        ## test - check edge added
        print(ind, end = ': ' )
        print(B_sort[ind][0], end=', ')
        print(dummyNode)
        """
        G.add_edge(B_sort[idx][0],dummyNode)
        G.add_edge(dummyNode,B_sort[idx][0])

def dummy_edge_high_BC_static(G,node_to_add):
    #average degree
    D = list(map(lambda x : x[1], list(G.degree(G.nodes))))
    edge_to_add = int(np.mean(D))
    #calculate betweenness centrality.
    B = nx.betweenness_centrality(G)
    #calculate sorted betweenness centrality list.
    B_sort = list(reversed(sorted(B.items(),key=(lambda x:x[1]))))
    #iterate for number of dummy nodes.
    for dummy_node in range(0, node_to_add):
        #add dummy node
        G.add_node(G.number_of_nodes())
        dummyNode = G.number_of_nodes()-1
        #add dummy edge
        for idx in range(0, edge_to_add):
            G.add_edge(B_sort[idx][0],dummyNode)
            G.add_edge(dummyNode,B_sort[idx][0])

def dummy_edge_high_BC_weighted_choice(G,node_to_add,destination_node):
    #average degree
    D = list(map(lambda x : x[1], list(G.degree(G.nodes))))
    edge_to_add = int(np.mean(D))
    #calculate betweenness centrality.
    DegreeDict = {};
    DummyDegreeDict = {};
    #calculate betweenness centrality.
    Bdict = nx.betweenness_centrality_subset(G,sources=set(G.nodes()),targets=set({destination_node}))
    B = []
    for key in Bdict.keys():
        B.append((key,Bdict[key]))
        DegreeDict[key] = G.degree[key];
        DummyDegreeDict[key] = 0;
    #Weighted k-sampling
    for dummy in range(0, node_to_add):
        Bdg = []
        for element in B:
            m = DegreeDict[element[0]]
            n = DummyDegreeDict[element[0]]
            Bdg.append((element[0],element[1]))
        target_nodes = random.choices(list(map(lambda x : x[0], Bdg)),weights=list(map(lambda x : x[1], Bdg)),k=edge_to_add)
        #add dummy node
        G.add_node(G.number_of_nodes())
        dummyNode = G.number_of_nodes()-1
        #add dummy edge
        for target in target_nodes:
            G.add_edge(target,dummyNode);
            G.add_edge(dummyNode,target);
            DummyDegreeDict[target]+=1;


#deprecated : required to use weighted choice method
'''
def dummy_edge_high_BC_round_robin(G,node_to_add):
    #average degree
    D = list(map(lambda x : x[1], list(G.degree(G.nodes))))
    edge_to_add = int(np.mean(D))
    #calculate betweenness centrality.
    B = nx.betweenness_centrality(G)
    Linked_node = set(G.nodes)
    for dummy in range(0, node_to_add):
        '''
def dummy_edge_mix_BC(G):
    #average degree
    D = list(map(lambda x : x[1], list(G.degree(G.nodes))))
    edge_to_add = int(np.mean(D)*0.5)
    #calculate betweenness centrality.
    B = nx.betweenness_centrality(G)
    #calculate sorted betweenness centrality list.
    B_sort = sorted(B.items(),key=(lambda x:x[1]))
    B_sort_reversed = list(reversed(sorted(B.items(),key=(lambda x:x[1]))))
    """
    ##test - check betweenness centrality sorted
    for i in B_sort:
        print(i, end=', ');
    print()
    for i in B_sort_reversed:
        print(i, end=', ');
    print()
    """
    #add dummy node
    G.add_node(G.number_of_nodes())
    dummyNode = G.number_of_nodes()-1
    for idx in range(0,edge_to_add):
        """
        ## test - check edge added
        print(idx, end = ': ' )
        print(B_sort[idx][0], end=' --  ')
        print(dummyNode, end=', ')
        print(B_sort_reversed[idx][0], end=' --  ')
        print(dummyNode)
        """
        G.add_edge(dummyNode,B_sort[idx][0])
        G.add_edge(B_sort[idx][0],dummyNode)
        G.add_edge(dummyNode,B_sort_reversed[idx][0])
        G.add_edge(B_sort_reversed[idx][0],dummyNode)

def dummy_edge_mix_BC_weighted_choice(G,node_to_add,destination_node):
    #average degree
    D = list(map(lambda x : x[1], list(G.degree(G.nodes))))
    edge_to_add = int(np.mean(D)*0.5)
    DegreeDict = {};
    DummyDegreeDict = {};
    #calculate betweenness centrality.
    Bdict = nx.betweenness_centrality_subset(G,sources=set(G.nodes()),targets=set({destination_node}))
    B = []
    for key in Bdict.keys():
        B.append((key,Bdict[key]))
        DegreeDict[key] = G.degree[key];
        DummyDegreeDict[key] = 0;
    #Weighted k-sampling
    for dummy in range(0, node_to_add):
        Bdg = []
        for element in B:
            m = DegreeDict[element[0]]
            n = DummyDegreeDict[element[0]]
            Bdg.append((element[0],element[1]))
        target_nodes1 = random.choices(list(map(lambda x : x[0], Bdg)),weights=list(map(lambda x : x[1], Bdg)),k=edge_to_add)
        target_nodes2 = random.choices(list(map(lambda x : x[0], Bdg)),weights=list(map(lambda x : 1-x[1], Bdg)),k=edge_to_add)
        while len(list(set(target_nodes1).intersection(target_nodes2))) > 0:
            target_nodes1 = random.choices(list(map(lambda x : x[0], Bdg)),weights=list(map(lambda x : x[1], Bdg)),k=edge_to_add)
            target_nodes2 = random.choices(list(map(lambda x : x[0], Bdg)),weights=list(map(lambda x : 1-x[1], Bdg)),k=edge_to_add)
        target_nodes = target_nodes1+target_nodes2
        #add dummy node
        G.add_node(G.number_of_nodes())
        dummyNode = G.number_of_nodes()-1
        #add dummy edge
        for target in target_nodes:
            G.add_edge(target,dummyNode);
            G.add_edge(dummyNode,target);
            DummyDegreeDict[target]+=1;

def degree_based(G):
    #average degree
    D = list(map(lambda x : x[1], list(G.degree(G.nodes))))
    D_mean = int(np.mean(D))
    #degree based reversely sorted list
    sorted_nodelist = list(reversed(sorted(list(G.degree(G.nodes())), key=(lambda x:x[1]))))
    """
    ##test - check betweenness centrality sorted
    for i in sorted_nodelist:
        print(i, end=', ');
    print()
    """
    #add dummy node
    G.add_node(G.number_of_nodes())
    dummyNode = G.number_of_nodes()-1
    #add dummy edge
    edge_to_add = D_mean
    for idx in range(0,edge_to_add):
        """ 
        ## test - check edge added
        print(idx, end = ': ' )
        print(sorted_nodelist[idx][0], end=' -- ')
        print(dummyNode)
        """
        G.add_edge(sorted_nodelist[idx],dummyNode)
        G.add_edge(dummyNode,sorted_nodelist[idx])

def A1(G, source_node, destination_node, originGraphSize):
    result = set()
    Q = []
    #initial append to queue Q
    Q.append(source_node)
    #DFS routine
    while len(Q) > 0:
        #Selecting node from queue Q.
        current_node = Q.pop()
        #Add current to node found(result)
        result.add(current_node)
        #If current node is destination node, return value and exit.
        if current_node == destination_node:
            return len(result)
        #If current node is a dummy node, pass it.
        if current_node >= originGraphSize:
            continue
        #bring all linked node from current node.
        nodes_nearby_set = set(map(lambda x : x[1], list(G.edges(current_node))))
        #delete visited nodes from found nodes.
        nodes_nearby_set -= result
        nodes_nearby = list(nodes_nearby_set)
        #shuffle nodes found to give randomness in DFS.
        random.shuffle(nodes_nearby)
        #append it to queue.
        Q += nodes_nearby
        
def A2(G,source_node,destination_node,mincut, originGraphSize):
    #find paths
    P = []
    #find all path from given source and destination node. All paths' length are same or less than mincut
    for path in nx.all_simple_paths(G, source=source_node,target=destination_node,cutoff=mincut-1):
        P.append(path)
    #shuffle list to give randomness.
    random.shuffle(P)
    #sort path list according to its length
    sortedP = list(sorted(P, key=(lambda x : len(x))))

    #since, paths in P have node same or less than mincut, we don't need to check length.
    real = False
    length = 0
    #result is set of nodes visited.
    result = set();
    #do it with every path
    for path in sortedP:
        for node in path:
            #Attacker inspect node. Therefore, we put the node in to the result set.
            result.add(node)
            #If dummy node is found, attacker will stop 
            if(node >= originGraphSize):
                break;
    return len(result)

def A3(G, source_node, destination_node, originGraphSize):
    result = set()
    Q = []
    #initial append to queue Q
    Q.append(source_node)
    #DFS routine
    while len(Q) > 0:
        #Selecting node from queue Q.
        current_node = Q.pop()
        #Add current to node found(result)
        result.add(current_node)
        #If current node is destination node, return value and exit.
        if current_node == destination_node:
            return len(result)
        #If current node is a dummy node, pass it.
        if current_node >= originGraphSize:
            continue
        #bring all linked node from current node.
        nodes_nearby_set = set(map(lambda x : x[1], list(G.edges(current_node))))
        #delete visited nodes from found nodes.
        nodes_nearby_set -= result
        nodes_nearby = list(nodes_nearby_set)
        #shuffle nodes found to give randomness in DFS.
        random.shuffle(nodes_nearby)
        #append it to queue.
        Q = nodes_nearby + Q

def mincut(G, source_node, destination_node):
    return len(list(nx.all_shortest_paths(G,source=source_node,target=destination_node))[0])

def extract_src_dst(G):
    #setting source and destination node by random.
    source_node = np.random.choice(G.nodes())
    destination_node = np.random.choice(G.nodes())
    while source_node==destination_node:
        source_node = np.random.choice(G.nodes())
        destination_node = np.random.choice(G.nodes())
    return source_node, destination_node

G=nx.DiGraph()
for x in range(0,9):
    G.add_node(x)
G.add_edge(0,1)
G.add_edge(0,2)
G.add_edge(1,3)
G.add_edge(2,3)
G.add_edge(1,7)
G.add_edge(2,8)
G.add_edge(7,4)
G.add_edge(3,4)
G.add_edge(3,5)
G.add_edge(8,5)
G.add_edge(4,6)
G.add_edge(5,6)



adjMat = input("Enter file name: ")
Gbase = extract_graph_from_adjacent_matrix(adjMat)
D = list(map(lambda x : x[1], list(Gbase.degree(Gbase.nodes))))
D_mean = int(np.mean(D))
print("edge desity: ", end='')
print(D_mean/100)
print("graph size: ", end='')
print(Gbase.number_of_nodes())

graphSize = Gbase.number_of_nodes()
dummyNode_num = int(graphSize * 0.2)   ##dummy node number

for i in range(100):              ## iteration time ##
    #random source & destination
    (source_node,destination_node) = extract_src_dst(Gbase);
    print("source node: ", end='')
    print(source_node, end=', ')
    print("destination node: ", end='')
    print(destination_node)
    Mincut = mincut(Gbase,source_node,destination_node);
    
    #Graphs after heuristic
    Grandom = Gbase.copy()
    randomly_added(Grandom,dummyNode_num)
    GHighBC = Gbase.copy()
    dummy_edge_high_BC_weighted_choice(GHighBC,dummyNode_num,destination_node)
    GLowBC = Gbase.copy()
    dummy_edge_low_BC_weighted_choice(GLowBC,dummyNode_num,destination_node)
    GMixBC = Gbase.copy()
    dummy_edge_mix_BC_weighted_choice(GMixBC,dummyNode_num,destination_node)
    
    base = 0
    rd = 0
    highBC = 0
    lowBC = 0
    mixBC = 0
    #Results for A1
    for a in range(100):
        base = base + A1(Gbase,source_node,destination_node, graphSize)
        rd = rd + A1(Grandom,source_node,destination_node, graphSize)
        highBC = highBC + A1(GHighBC,source_node,destination_node, graphSize)
        mixBC = mixBC + A1(GMixBC,source_node,destination_node, graphSize)
        lowBC = lowBC + A1(GLowBC,source_node,destination_node, graphSize)
    base = base/100
    rd = rd / 100
    highBC = highBC / 100
    lowBC = lowBC / 100
    mixBC = mixBC / 100
    print(base, end='   ')
    print(rd, end='   ')
    print(highBC, end='   ')
    print(mixBC, end='   ')
    print(lowBC, end='   |   ')
    
    #Results for A2
    for a in range(100):
        base = base + A2(Gbase,source_node,destination_node, Mincut, graphSize)
        rd = rd + A2(Grandom,source_node,destination_node, Mincut, graphSize)
        highBC = highBC + A2(GHighBC,source_node,destination_node, Mincut, graphSize)
        mixBC = mixBC + A2(GMixBC,source_node,destination_node, Mincut, graphSize)
        lowBC = lowBC + A2(GLowBC,source_node,destination_node, Mincut, graphSize)
    base = base/100
    rd = rd / 100
    highBC = highBC / 100
    lowBC = lowBC / 100
    mixBC = mixBC / 100
    print(base, end='   ')
    print(rd, end='   ')
    print(highBC, end='   ')
    print(mixBC, end='   ')
    print(lowBC, end='   |   ')

    #Results for A3
    for a in range(100):
        base = base + A3(Gbase,source_node,destination_node, graphSize)
        rd = rd + A3(Grandom,source_node,destination_node, graphSize)
        highBC = highBC + A3(GHighBC,source_node,destination_node, graphSize)
        mixBC = mixBC + A3(GMixBC,source_node,destination_node, graphSize)
        lowBC = lowBC + A3(GLowBC,source_node,destination_node, graphSize)
    base = base/100
    rd = rd / 100
    highBC = highBC / 100
    lowBC = lowBC / 100
    mixBC = mixBC / 100
    print(base, end='   ')
    print(rd, end='   ')
    print(highBC, end='   ')
    print(mixBC, end='   ')
    print(lowBC)
    
