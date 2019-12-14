#include "struct.h"
#include "function.h"
#include "graph.h"
#include <ctime>
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>


#include <vector>
#include <queue>
#include <stack>
#include <algorithm>
#include <functional>
#include <random>
#include <chrono>

using namespace std;

bool cmp1(const degInfo &a, const degInfo &b){
	return a.NodeNumber < b.NodeNumber;	
}
bool cmp2(const degInfo &a, const degInfo &b)
{
	return a.Degree < b.Degree;
}


int degreeBased(Graph &G, int s, int f, double &totalTimeCost, vector<double> B, const TFheGateBootstrappingSecretKeySet *PK, const TFheGateBootstrappingCloudKeySet *EK)
{
//	srand(time(0));
	double timeCost = 0;
//	vector<double> B = normalizedBetweenness(G,EK);
	
	bool visitTable[G.node->size()];
	bool insertTable[G.node->size()];

	vector<int> Blacklist;
	int size = G.node->size();
	int **checkDuplicate = new int *[size];
	for(int i=0;i<size;i++)
	{
		checkDuplicate[i] = new int [size];
	}

	for(int i=0;i<size;i++)
	{
		for(int j=0;j<size;j++)
		{
			checkDuplicate[i][j]=0;
		}
	}


	int L = G.node->size();
	for(int i = 0; i < L ; i++)  // Initialize visit table
	{
		visitTable[i] = false;
		insertTable[i] = false;
	}

	int probeCount = 0;

	vector<degInfo> Vector;	       // stack used for graph search

	degInfo a;
	a.NodeNumber = s;
	
	Vector.push_back(a); // Initialize search stack

	while(Vector.size()>0)
	{
		// choose node number to search
		int largest = Vector.back().Degree;
		int Idx = Vector.size()-1;
		while(Vector[Idx].Degree == largest)
		{
			if(Idx == 0)	break;
			
			if(Vector[Idx-1].Degree == Vector[Idx].Degree)
			{
				Idx--;
			}
			else
			{
				break;
			}
		}
		int Number = Vector.size()-Idx;

		int SelectedIdx = Idx+rand()%Number;

		int currentNode = Vector[SelectedIdx].NodeNumber;
		Blacklist.push_back(currentNode);

		Vector.erase(Vector.begin()+SelectedIdx);	

		// Check whether it is ending condition.
		if(currentNode == f)
		{
			probeCount++;
			
			timeCost += B[f];
			totalTimeCost += timeCost;			
//			cout <<"degree based probe count : " <<probeCount <<endl;

			return probeCount;
		}

		// Check whether this is visited node.
		if(visitTable[currentNode] == true)
		{
			// if the node is visited, choose next node number to search
			// this means there would be no action with the node
			continue;
		}
		
		//check current node
//		cout << currentNode << endl;

		visitTable[currentNode] = true;
		probeCount++;

		timeCost += B[currentNode];

		// Choose the node
		nodeList C = findNode(G, currentNode);

		// Neighbor search
		list<Neighbor> *Ne = C.node->Neighbors;
		list<Neighbor>::iterator iter;

		for(iter = Ne->begin(); iter != Ne->end(); ++iter)
		{
			// if the edge is dummy edge, discard.
                        if(bootsSymDecrypt((*iter).T,PK) == 0)
                        {
                                continue;                                
                        }

			int neighborNode = (*iter).NodeNumber;
			nodeList Cn = findNode(G, neighborNode);

			struct degInfo tmp;
		
			if(insertTable[neighborNode] == false)
			{
				insertTable[neighborNode] = true;
				tmp.NodeNumber = neighborNode;
				tmp.Degree     = Cn.node->Neighbors->size();
				Vector.push_back(tmp);
			}
		}

		// Degree modification
		int L = Vector.size();
		for(int i = 0; i < L; i++)
		{
			nodeList C = findNode(G,Vector[i].NodeNumber);
			list<Neighbor> *Ne = C.node->Neighbors;
			list<Neighbor>::iterator iter;

			for(iter = Ne->begin(); iter != Ne->end(); ++iter)
			{
				int B = Blacklist.size();
				for(int j = 0; j < B; j++)
				{
					if(Blacklist[j] == (*iter).NodeNumber && checkDuplicate[Vector[i].NodeNumber][Blacklist[j]]==0)
					{
						Vector[i].Degree--;
						checkDuplicate[Vector[i].NodeNumber][Blacklist[j]]=1;
						break;
					}
				}
			}
		}
		/*
		sort(Vector.begin(),Vector.end(),cmp1);
		auto comp = [] ( const degInfo& lhs, const degInfo& rhs ) {return lhs.NodeNumber == rhs.NodeNumber;};
                auto last = std::unique(Vector.begin(), Vector.end(),comp);
                Vector.erase(last, Vector.end());	
		*/
		sort(Vector.begin(),Vector.end(),cmp2);
	
		// Print debug part TODO = delete after complete this part.
/*
		//check left nodes which can be connected		
		for(int i = 0 ; i < Vector.size(); i++)
		{
			cout << Vector[i].NodeNumber << ", " << Vector[i].Degree << endl;
		}
		cout << " --------------- " << endl;
*/
	}

	printf("Degree based : There is no path...\n");
	return 0;
}


int BFSattack(Graph &G, int s, int f, double &totalTimeCost, vector<double> B, const TFheGateBootstrappingSecretKeySet *PK, const TFheGateBootstrappingCloudKeySet *EK)
{
	double timeCost = 0;
//	vector<double> B = normalizedBetweenness(G, EK);
	
	int visitCount = 0;

	bool visitTable[G.node->size()];
	int L = G.node->size();
	for(int i = 0; i < L ; i++)  // Initialize visit table
	{
		visitTable[i] = false;
	}

	queue<int> Queue;		// queue used for graph search	

	Queue.push(s);

	while(Queue.size()>0)
	{
		int currentNode = Queue.front();
		Queue.pop();
	
		if(currentNode == f)
		{
			visitCount++;
			
			timeCost += B[f];
			totalTimeCost += timeCost;
//			cout <<"BFS probe count : " <<visitCount <<endl;

			return visitCount;
		}	
 
		if(visitTable[currentNode] == false)
		{
			visitCount++;

			timeCost += B[currentNode];
	
			visitTable[currentNode] = true;

			nodeList C = findNode(G, currentNode);
			list<Neighbor> *Ne = C.node->Neighbors;
			list<Neighbor>::iterator iter;
		
			vector<int> temp;

			for(iter = Ne->begin(); iter != Ne->end(); ++iter)
			{
				// if the edge is dummy edge, discard.
				if(bootsSymDecrypt((*iter).T,PK) == 0)
				{
					continue;					
				}

				int neighborNode = (*iter).NodeNumber;
				if(visitTable[neighborNode]==false)
				{
					temp.push_back(neighborNode);
//					Queue.push(neighborNode);
				}
			}

			unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
                        std::shuffle(temp.begin(), temp.end(), std::default_random_engine(seed));

                        int size = temp.size();

                        for(int i=0;i<size;i++){
                                Queue.push(temp[i]);
                        }

		}
	}
	printf("BFS : There is no path...\n");
	return 0;
}


int DFSattack(Graph &G, int s, int f, double &totalTimeCost, vector<double> B, const TFheGateBootstrappingSecretKeySet *PK, const TFheGateBootstrappingCloudKeySet *EK)
{
	clock_t start, end;
	double timeCost = 0;
	int visitCount = 0;
        bool visitTable[G.node->size()];
        int L = G.node->size();
        for(int i = 0; i < L ; i++){
                visitTable[i] = false;
        }
        stack<int> Stack;                 
        Stack.push(s);
        while(Stack.size()>0){
                int currentNode = Stack.top();
                Stack.pop();
		
                if(currentNode == f){
                        visitCount++;
                        return visitCount;
                }
                if(visitTable[currentNode] == false){
                        visitCount++;
                        visitTable[currentNode] = true;
                        nodeList C = findNode(G, currentNode);
			// if the node is dummy node, discard.
			if(bootsSymDecrypt(C.node->T,PK) == false){
				continue;
			}

                        list<Neighbor> *Ne = C.node->Neighbors;
                        list<Neighbor>::iterator iter;
			vector<int> temp;
                        for(iter = Ne->begin(); iter != Ne->end(); ++iter)
                        {
				// if the edge is dummy edge, discard.
                                if(bootsSymDecrypt((*iter).T,PK) == 0)
                                {
                                        continue;                                
                                }

                                int neighborNode = (*iter).NodeNumber;
               			if(visitTable[neighborNode] == false)
				{
					temp.push_back(neighborNode);
                        	}
			}
		
			unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
			std::shuffle(temp.begin(), temp.end(), std::default_random_engine(seed));
			int size = temp.size();
/*
			//check vector shuffled
			for(int i=0;i<size;i++){
				cout << temp[i] <<", ";
			}
			cout <<endl;
*/		
			for(int i=0;i<size;i++){
				Stack.push(temp[i]);
			}
                }
        }
	
//	printf("\nDFS : There is no path...\n");
	return 0;	
}

int restrictedDFSattack(Graph &G, int s, int f, double &totalTimeCost, vector<double> B, const TFheGateBootstrappingSecretKeySet *PK, const TFheGateBootstrappingCloudKeySet *EK){
	clock_t start, end;
	double timeCost = 0;
	int visitCount = 0;
	int length = 0;
	bool visitTable[G.node->size()];
	int L = G.node->size();
	for(int i = 0; i < L ; i++){
                visitTable[i] = false;
        }

        stack<int> Stack;                
        Stack.push(s);
	length++;
        while(Stack.size()>0){
                int currentNode = Stack.top();
                Stack.pop();
	
		if(length > (int)(0.9 * (double)L)){
			length--;
//			cout <<"len exceed" <<endl;
			continue;
		}
		else{
	                if(currentNode == f){
	                        visitCount++;
				length ++;
	//                        totalTimeCost += timeCost;
	                        return visitCount;
	                }
	
	                if(visitTable[currentNode] == false){
	                        visitCount++;
	                        visitTable[currentNode] = true;
	                        nodeList C = findNode(G, currentNode);
				if(bootsSymDecrypt(C.node->T,PK) == false){
	                                continue;
	                        }
	
	                        list<Neighbor> *Ne = C.node->Neighbors;
	                        list<Neighbor>::iterator iter;
	
	                        vector<int> temp;
	                        for(iter = Ne->begin(); iter != Ne->end(); ++iter){
	                                // if the edge is dummy edge, discard.
	                                if(bootsSymDecrypt((*iter).T,PK) == 0)
	                                {
	                                        continue;
	                                }
	
	                                int neighborNode = (*iter).NodeNumber;
	                                if(visitTable[neighborNode] == false)
	                                {
	                                        temp.push_back(neighborNode);
	                                }
	                        }
	                        unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
	                        std::shuffle(temp.begin(), temp.end(), std::default_random_engine(seed));
	
	                        int size = temp.size();
				if(size ==0){
					length--;
				}
	
	                        for(int i=0;i<size;i++){
	                                Stack.push(temp[i]);
	                        }
				length++;
	                }
		}
        }
        return 0;
}
