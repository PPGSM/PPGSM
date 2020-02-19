#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <queue>
#include <vector>
#include <cmath>
#include <algorithm>
#include <iostream>

#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>

#include "structure/struct.h"
#include "utility/graph_client.h"
#include "structure/graph.h"

using namespace std;

//////////////		Make an initial graph		///////////////


/////////////////	Metric about security of dummy elements		/////////////////////

//calculate entropy of centralities by using Shannon Entropy
double getEntrophy(std::vector<double> L)		{
        double entrophy = 0;
        double b=2;					//initial value of b can also be 10
        int s = L.size();

	sort(L.begin(),L.end());
	
	std::vector<double> num;	
	int temp = 1;	

        for(int i=1; i<s; i++){
		if(L[i]==L[i-1]){
			temp++;
		}
		else{
                	num.push_back(temp);
			temp = 1;
		}
        }

	num.push_back(temp);
	int t = num.size();

	for(int i=0; i<t; i++){
		num[i] /= s;
	}

        for(int i=0; i<t; i++){
                entrophy += num[i]*log(1/num[i])/log(b);
        }
        return entrophy;
}

//calculate standard deviation of centralities.
double standardDeviation(std::vector<double> L){
	double V = 0;	
	double mean = 0;
	int S = L.size();
	for(int i = 0; i < S; i++){
		mean+=L[i];
	}
	mean/=(double)S;

	for(int i = 0; i < S; i++){
		V += (L[i]-mean) * (L[i]-mean);
	}
	V/=(double)S;
	return sqrt(V);
}


//metric 'shortest hop' which means a minimum hops to know all dummy elements
int sh(struct Graph& G, int a, int t, const TFheGateBootstrappingSecretKeySet *PK){
	int Gsize = G.node->size();
	RevBFSTreeNode N[Gsize];	
	for(int i = 0 ; i < Gsize; i++){
		N[i].nodeNum   = i;
		N[i].visited   = 0;
		N[i].score     = 0;
		N[i].invInEdge = 0;
	}

	queue<int> BFSQueue;
	queue<int> InvSearchQueue;
	BFSQueue.push(a);
	N[a].visited = 1;

	std::list<struct nodeList>::iterator iter;
	std::list<struct Neighbor>::iterator iter2;

	while(BFSQueue.size() > 0){
		int Num = BFSQueue.front();
		BFSQueue.pop();
		for(iter = G.node->begin(); (*iter).node->NodeNumber != Num; ++iter);	
		std::list<struct Neighbor> *E = (*iter).node->Neighbors;
		int cnt = 0;

		for(iter2 = E->begin(); iter2 != E->end(); ++iter2){
			int x = (*iter2).NodeNumber;
			std::cout << x << std::endl;
			if(N[x].visited == 0 && bootsSymDecrypt((*iter2).T,PK) == 1){ // If it is not visited and it is true edge
				cnt++;
				BFSQueue.push((*iter2).NodeNumber);
				N[x].REdge = &N[Num];
				N[Num].invInEdge++;
				N[x].visited = 1;
			}
			else if(bootsSymDecrypt((*iter2).T,PK) == 0){ // If it is dummy edge
				N[Num].score++;
			}
		}

		if(cnt == 0){
			InvSearchQueue.push(Num);
		}
	}

	for(int i=0;i<G.node->size();i++){
		cout << N[i].score << endl;	
	}

	while(InvSearchQueue.size() > 0){
		int Num = InvSearchQueue.front();
		InvSearchQueue.pop();
		if(N[Num].invInEdge == 0){
			int NNum = N[Num].REdge->nodeNum;
			N[NNum].invInEdge--;
			if(N[Num].score > 0){
				N[NNum].score+=(N[Num].score+1);
			}
			if(NNum != a){
				InvSearchQueue.push(NNum);
			}
			N[Num].invInEdge = 1;
		}
	}
	return N[a].score;
}

//get a value of 'dr1 = (number of paths containing dummy elements) / (number of all possible paths)'
void dr_probe(struct Graph& G, int &DpathNum, int &pathNum, struct nodeList* N, LweSample* Tmp, int dest, const TFheGateBootstrappingSecretKeySet* PK){
        N->visited = true;
        if(N->node->NodeNumber == dest){
		pathNum++;
		if(bootsSymDecrypt(Tmp,PK) == 0){ // If it is true path
			DpathNum++;	
		}
        }
        else{       
                list<struct Neighbor>::iterator iter;

                for(iter = N->node->Neighbors->begin(); iter != N->node->Neighbors->end(); ++iter){       
                        list<struct nodeList>::iterator iter2; 
                        for(iter2 = G.node->begin(); iter2 != G.node->end(); ++iter2){       
                                if((*iter).NodeNumber == (*iter2).node->NodeNumber && (*iter2).visited == false){       
                                        /* Validity bit stage */
                                        LweSample *Temp = new_gate_bootstrapping_ciphertext((&PK->cloud)->params);
                                        bootsAND(Temp, (*iter).T, Tmp, &PK->cloud);

                                        dr_probe(G, DpathNum, pathNum, &(*iter2), Temp, dest, PK);
                                }
                        }
                }
        }

        N->visited = false;
}

//initial function for calculate dr1 (improve usability)
double dr(struct Graph& G, int a, int t, const TFheGateBootstrappingSecretKeySet *PK){
	list<struct nodeList>::iterator iter;
	for(iter = G.node->begin(); (*iter).node->NodeNumber != a; ++iter);

	LweSample *T = new_gate_bootstrapping_ciphertext((&PK->cloud)->params);
        bootsCONSTANT(T, 1, (&PK->cloud));

	int totalPath = 0;
	int dummyPath  = 0;	

	dr_probe(G, dummyPath, totalPath, &(*iter), T, t, PK);
	
	cout << totalPath <<'\t' << dummyPath <<'\t';
	return (double)dummyPath / (double)totalPath; 
}

//get a value of 'dr2 = (number of the shortest paths containing dummy elements) / (number of the shoetest paths)'
void dr_probeShortest(struct Graph& G, int &length, int &temp, int &DpathNum, int &pathNum, struct nodeList* N, LweSample* Tmp, int dest, const TFheGateBootstrappingSecretKeySet* PK){     
	N->visited = true;
	length++;

        if(N->node->NodeNumber == dest){
		if(length == temp){
                	pathNum++;
		
                	if(bootsSymDecrypt(Tmp,PK) == 0){ // If it is dummy path
                        	DpathNum++;
                	}
		}
		else if(length<temp){
			DpathNum = 0;		
			pathNum = 0;
			pathNum++;
			temp = length;		
	
			if(bootsSymDecrypt(Tmp,PK)==0){
				DpathNum++;
			}
		}
        }
        else{
                list<struct Neighbor>::iterator iter;
		
                for(iter = N->node->Neighbors->begin(); iter != N->node->Neighbors->end(); ++iter){
                        list<struct nodeList>::iterator iter2; 
                        for(iter2 = G.node->begin(); iter2 != G.node->end(); ++iter2){
                                if((*iter).NodeNumber == (*iter2).node->NodeNumber && (*iter2).visited == false){
                                        /* Validity bit stage */
                                        LweSample *Temp = new_gate_bootstrapping_ciphertext((&PK->cloud)->params);
                                        bootsAND(Temp, (*iter).T, Tmp, &PK->cloud);
						
                                        dr_probeShortest(G, length, temp, DpathNum, pathNum, &(*iter2), Temp, dest, PK);
                                }
                        }
                }
        }

        N->visited = false;
	length--;
	return;
}

//initial function to calculate dr2 (improve usability)
double drShortest(struct Graph& G, int a, int t, const TFheGateBootstrappingSecretKeySet *PK){
        list<struct nodeList>::iterator iter;
        for(iter = G.node->begin(); (*iter).node->NodeNumber != a; ++iter);

        LweSample *T = new_gate_bootstrapping_ciphertext((&PK->cloud)->params);
        bootsCONSTANT(T, 1, (&PK->cloud));

	int length = 0;
	int temp = 10000;
        int totalShortestPath = 0;
        int dummyShortestPath  = 0;

        dr_probeShortest(G, length, temp, dummyShortestPath, totalShortestPath, &(*iter), T, t, PK);

	cout <<"minLength : " <<  temp-1;
        cout <<" totalShortestPath : " << totalShortestPath << " dummyShortestPath : " << dummyShortestPath << endl;

        return (double)dummyShortestPath / (double)totalShortestPath;
}


//get a value of 'dr3 = (total number of dummy edges in dummy paths) / (total length of all paths)'
void dr_probeLength(struct Graph& G, int &tempLength, int &tempDummyLength, int &DpathNum, int &pathNum, struct nodeList* N, LweSample* Tmp, int dest, const TFheGateBootstrappingSecretKeySet* PK){
        N->visited = true;

        if(N->node->NodeNumber == dest){
                pathNum += tempLength;
                DpathNum += tempDummyLength;
           
        }
        else{
                list<struct Neighbor>::iterator iter;

                for(iter = N->node->Neighbors->begin(); iter != N->node->Neighbors->end(); ++iter){
                        list<struct nodeList>::iterator iter2; 
                        for(iter2 = G.node->begin(); iter2 != G.node->end(); ++iter2){
                                if((*iter).NodeNumber == (*iter2).node->NodeNumber && (*iter2).visited == false){
                                        /* Validity bit stage */
                                        LweSample *Temp = new_gate_bootstrapping_ciphertext((&PK->cloud)->params);
                                        bootsAND(Temp, (*iter).T, Tmp, &PK->cloud);
					tempLength++;
					if(bootsSymDecrypt((*iter).T,PK)==0){
						tempDummyLength ++;
					}					

                                        dr_probeLength(G,tempLength, tempDummyLength, DpathNum, pathNum, &(*iter2), Temp, dest, PK);
					tempLength--;
					if(bootsSymDecrypt((*iter).T,PK)==0){
                                                tempDummyLength --;
                                        }

                                }
                        }
                }
        }

        N->visited = false;
}

//initial function to get dr3 (improve usability)
double drLength(struct Graph& G, int a, int t, const TFheGateBootstrappingSecretKeySet *PK){
        list<struct nodeList>::iterator iter;
        for(iter = G.node->begin(); (*iter).node->NodeNumber != a; ++iter);

        LweSample *T = new_gate_bootstrapping_ciphertext((&PK->cloud)->params);
        bootsCONSTANT(T, 1, (&PK->cloud));

        int tempLength = 0;
        int tempDummyLength = 0;
        int totalLength = 0;
        int dummyLength  = 0;

        dr_probeLength(G, tempLength, tempDummyLength, dummyLength, totalLength, &(*iter), T, t, PK);

        cout << "totalLength : " << totalLength;
        cout << " dummyLength : " << dummyLength <<endl;

        return (double)dummyLength / (double)totalLength;
}

//get a value of 'dr4 = (number of dummy edges in the shortest dummy paths) / (total length of the shortest paths)
void dr_probeShortestLength(struct Graph& G, int &length, int &temp, int &tempLength, int &tempDummyLength,  int &DpathNum, int &pathNum, struct nodeList* N, LweSample* Tmp, int dest, const TFheGateBootstrappingSecretKeySet* PK){
        length++;
        N->visited = true;

        if(N->node->NodeNumber == dest){
                if(length == temp){
                        pathNum += (length-1);

                        if(bootsSymDecrypt(Tmp,PK) == 0){ // If it is dummy path
                                DpathNum += tempDummyLength;
                        }
                }
                else if(length<temp){
                        DpathNum = 0;
                        pathNum = (length-1);
                        temp = length;

                        if(bootsSymDecrypt(Tmp,PK)==0){
                                DpathNum += tempDummyLength;
                        }
                }

        }
	else{
		list<struct Neighbor>::iterator iter;
                for(iter = N->node->Neighbors->begin(); iter != N->node->Neighbors->end(); ++iter){
                        list<struct nodeList>::iterator iter2;
                        for(iter2 = G.node->begin(); iter2 != G.node->end(); ++iter2){
                                if((*iter).NodeNumber == (*iter2).node->NodeNumber && (*iter2).visited == false){
                                        /* Validity bit stage */
                                        LweSample *Temp = new_gate_bootstrapping_ciphertext((&PK->cloud)->params);
                                        bootsAND(Temp, (*iter).T, Tmp, &PK->cloud);

                                        if(bootsSymDecrypt((*iter).T,PK)==0){
                                                tempDummyLength ++;
                                        }

                                        dr_probeShortestLength(G, length, temp, tempLength, tempDummyLength, DpathNum, pathNum, &(*iter2), Temp, dest, PK);

                                        if(bootsSymDecrypt((*iter).T,PK)==0){
                                                tempDummyLength --;
                                        }

                                }
                        }
                }
        }

        length--;
        N->visited = false;
}

//initial function to calculate dr4 (improve usability)
double drShortestLength(struct Graph& G, int a, int t, const TFheGateBootstrappingSecretKeySet *PK){
        list<struct nodeList>::iterator iter;
        for(iter = G.node->begin(); (*iter).node->NodeNumber != a; ++iter);

        LweSample *T = new_gate_bootstrapping_ciphertext((&PK->cloud)->params);
        bootsCONSTANT(T, 1, (&PK->cloud));

        int length = 0;
        int temp = 10000;
        int tempLength = 0;
        int tempDummyLength = 0;
        int totalShortestLength = 0;
        int dummyShortestLength  = 0;

        dr_probeShortestLength(G, length, temp, tempLength, tempDummyLength, dummyShortestLength, totalShortestLength, &(*iter), T, t, PK);

        cout <<"totalShortestLength : " << totalShortestLength;
        cout <<" dummyShortestLength : " <<dummyShortestLength <<endl;

        return (double)dummyShortestLength / (double)totalShortestLength;
}
   


////////////////////	Generating Cost part	//////////////////////////

//a function which is helpful to count a number of dummy nodes
void dr_probeLength_var(struct Graph& G, int &dummyNode, struct nodeList* N, LweSample* Tmp, int dest, const TFheGateBootstrappingSecretKeySet* PK){
        N->visited = true;
	if(bootsSymDecrypt(N->node->T,PK)==0){
		dummyNode++;
	}

        if(N->node->NodeNumber == dest){
        }
        else{
                list<struct Neighbor>::iterator iter;

                for(iter = N->node->Neighbors->begin(); iter != N->node->Neighbors->end(); ++iter){
                        list<struct nodeList>::iterator iter2; 
                        for(iter2 = G.node->begin(); iter2 != G.node->end(); ++iter2){
                                if((*iter).NodeNumber == (*iter2).node->NodeNumber && (*iter2).visited == false){
                                        /* Validity bit stage */
                                        LweSample *Temp = new_gate_bootstrapping_ciphertext((&PK->cloud)->params);
                                        bootsAND(Temp, (*iter).T, Tmp, &PK->cloud);

                                        dr_probeLength_var(G,dummyNode, &(*iter2), Temp, dest, PK);
                                }
                        }
                }
        }

        N->visited = false;
}


//count a number of dummy edges
//it is used on calculating first type of generating cost
int dEdge(struct Graph& G, int a, int t, const TFheGateBootstrappingSecretKeySet *PK){
	list<struct nodeList>::iterator iter;
        for(iter = G.node->begin(); (*iter).node->NodeNumber != a; ++iter);

        LweSample *T = new_gate_bootstrapping_ciphertext((&PK->cloud)->params);
        bootsCONSTANT(T, 1, (&PK->cloud));

        int tempLength = 0;
        int tempDummyLength = 0;
        int totalLength = 0;
        int dummyLength  = 0;

        dr_probeLength(G, tempLength, tempDummyLength, dummyLength, totalLength, &(*iter), T, t, PK);
	return dummyLength;
}


//count a number of dummy nodes
//it is used in calculating first type of generating cost
int dNode(struct Graph& G, int a, int t, const TFheGateBootstrappingSecretKeySet *PK){
	list<struct nodeList>::iterator iter;
        for(iter = G.node->begin(); (*iter).node->NodeNumber != a; ++iter);

        LweSample *T = new_gate_bootstrapping_ciphertext((&PK->cloud)->params);
        bootsCONSTANT(T, 1, (&PK->cloud));

        int dummyNode  = 0;

        dr_probeLength_var(G, dummyNode, &(*iter), T, t, PK);
	return dummyNode;
}


//get a value of first type of generating cost
double dummyGeneratingCost(struct Graph& G, int a, int t, const TFheGateBootstrappingSecretKeySet *PK, double w1, double w2){
	double result;
	result = w1 *(double)dNode(G,a,t,PK) + w2 * (double)dEdge(G,a,t,PK);
	return result;
}


//calculate betweenness centralities of dummy elements
//it is used in calculate second type of generating cost
void getDummyBetweenness(struct Graph& G, std::vector<double> B, double &dNode, double &tempDEdge, double &dEdge, struct nodeList* N, LweSample* Tmp, int dest, const TFheGateBootstrappingSecretKeySet* PK){
	N->visited = true;
	if(bootsSymDecrypt(N->node->T,PK)==0){
		dNode += B[N->node->NodeNumber];
	}
	
	if(N->node->NodeNumber == dest){
        }

        else{
                list<struct Neighbor>::iterator iter;

                for(iter = N->node->Neighbors->begin(); iter != N->node->Neighbors->end(); ++iter){
                        list<struct nodeList>::iterator iter2; 
                        for(iter2 = G.node->begin(); iter2 != G.node->end(); ++iter2){
                                if((*iter).NodeNumber == (*iter2).node->NodeNumber && (*iter2).visited == false){
                                       
                                        LweSample *Temp = new_gate_bootstrapping_ciphertext((&PK->cloud)->params);
                                        bootsAND(Temp, (*iter).T, Tmp, &PK->cloud);

                                        getDummyBetweenness(G, B, dNode, tempDEdge, dEdge, &(*iter2), Temp, dest, PK);
	
					if(bootsSymDecrypt((*iter).T,PK)==0){
						dEdge += B[(*iter).NodeNumber];
						dEdge += B[N->node->NodeNumber];
                                        }

                                }
                        }
                }
        }

        N->visited = false;

}


//get a value of second type of generating cost
double dummyGeneratingCost2(struct Graph& G, int a, int t, const TFheGateBootstrappingSecretKeySet *PK, const TFheGateBootstrappingCloudKeySet *EK, double w1, double w2){
	list<struct nodeList>::iterator iter;
        for(iter = G.node->begin(); (*iter).node->NodeNumber != a; ++iter);

        LweSample *T = new_gate_bootstrapping_ciphertext((&PK->cloud)->params);
        bootsCONSTANT(T, 1, (&PK->cloud));

	double dNode = 0, tempDEdge = 0, dEdge = 0;
	std::vector<double> B = normalizedBetweenness(G, EK);

 	getDummyBetweenness(G, B, dNode, tempDEdge, dEdge, &(*iter), T, t, PK);
	
	dEdge /= 2;
	double result = w1 * dNode + w2 * dEdge;
	return result; 
}


