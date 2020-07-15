#include "struct.h"
#include "../encryption.h"
#include "../utility/graph_client.h"
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>

// C++ based libraries.
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <vector>
#include <algorithm>
#include <functional>
#include <algorithm>
#include <set>
#include <time.h>
#include <iostream>
#include <random>
#include <fstream>
#include <queue>

#define  NODE_ID 8

using namespace std;
using namespace seal;

static bool operator <(degInfo &a, degInfo &b)
{
        return a.NodeNumber < b.NodeNumber;
}

	/* Finding a specific node in the graph using nodeNumber */
struct nodeList findNode(struct Graph &G, int nodeNumber){
        list<struct nodeList>::iterator iter;
        for(iter = G.node->begin(); (*iter).node->NodeNumber != nodeNumber; ++iter);
        return (*iter);
}

	/* Function that delete graph structure after analyzing */
void delete_graph(struct Graph& G)
{
	for(auto N : *(G.node))
	{
		struct node* Nn = N.node;
		for(auto Ne : *(Nn->Neighbors))
		{
			delete_gate_bootstrapping_ciphertext(Ne.T);
		}
		delete_gate_bootstrapping_ciphertext(Nn->T);

		delete(Nn->Neighbors);
		delete(Nn);
	}
}
		///////////////////////////////////////			
		// functions for security assessment //
		///////////////////////////////////////

	/* find all paths between two nodes with attack cost & risk */
void probe(struct Graph& G, Ciphertext cost, Ciphertext risk, struct nodeList &N, LweSample* Tmp, vector<int> path, int dest, const TFheGateBootstrappingCloudKeySet* EK, const TFheGateBootstrappingSecretKeySet *PK, Evaluator &eval, auto &relin_keys, std::shared_ptr<seal::SEALContext> context, auto &secret_key){
	N.visited = true;
//	std::ofstream out("pathInfo.txt", std::ios::app);
//	cout << N.node->NodeNumber << endl;
	if(N.node->user == false){
		//calculate attack cost
		eval.add_inplace(cost,N.node->Weight);
		//calculate risk
		Ciphertext Rst;
		eval.multiply(N.node->Impact,N.node->Pr,Rst);
		eval.relinearize_inplace(Rst,relin_keys);
		eval.rescale_to_next_inplace(Rst);
		parms_id_type last_parms_id = Rst.parms_id(); 
		Rst.scale() = pow(2.0,40);
		eval.mod_switch_to_inplace(risk, last_parms_id);
		eval.add(risk,Rst,risk);
	}
	path.push_back(N.node->NodeNumber);
	list<struct Neighbor>::iterator iter;

	if(N.node->NodeNumber == dest){
		//check a result
		cout << "path : ";
		for(auto P : path)
		{
			cout << P << " ";
		}
		cout << endl;
		Decryptor decryptor(context, secret_key);
                CKKSEncoder encoder(context);
                Plaintext cost_result, risk_result;
                decryptor.decrypt(cost, cost_result);
                decryptor.decrypt(risk,risk_result);
                vector<double> resultCost, resultRisk;
                encoder.decode(cost_result, resultCost);
                encoder.decode(risk_result, resultRisk);
                int real = bootsSymDecrypt(Tmp, PK);

		cout <<"cost: " <<resultCost[0] << endl;
		cout <<"risk: " <<resultRisk[0] <<endl;
		cout <<"real: " <<real <<endl;
		return;
        }
        else{
		for(iter = N.node->Neighbors->begin(); iter != N.node->Neighbors->end(); ++iter){
			list<struct nodeList>::iterator iter2;
			for(iter2 = G.node->begin(); iter2 != G.node->end(); ++iter2){
				if((*iter).NodeNumber == (*iter2).node->NodeNumber && (*iter2).visited == false){
					LweSample *Temp = new_gate_bootstrapping_ciphertext(EK->params);
					bootsAND(Temp,Tmp,(*iter).T,EK);
					probe(G, cost, risk, (*iter2), Temp, path, dest, EK, PK, eval, relin_keys, context, secret_key);
					(*iter2).visited = false;
				}
			}
		}
	}
	N.visited = false;
}

	/* Initial function to start probe (compute attack cost & risk) */
void init_probe(struct Graph& G, int startNumber, int destNumber, const TFheGateBootstrappingCloudKeySet* EK, const TFheGateBootstrappingSecretKeySet *PK, Evaluator &eval, seal::RelinKeys& relin_keys, seal::PublicKey public_key, std::shared_ptr<seal::SEALContext> context, seal::SecretKey secret_key){
	//make ciphertexts to store attack cost & risk (encoding -> encrypt)
	double scale = pow(2.0,40);
	CKKSEncoder encoder(context);
	Plaintext Cost,Risk;
	encoder.encode(0, scale, Cost);
	encoder.encode(0, scale, Risk);

	Encryptor encryptor(context, public_key);
	Ciphertext cost,risk;
	encryptor.encrypt(Cost,cost);
	encryptor.encrypt(Risk,risk);

	//set all nodes non-visited except start point
	for(auto inode : *(G.node)){
		inode.visited = false;
	}

	list<struct nodeList>::iterator iter;
	for(iter = G.node->begin(); iter != G.node->end();++iter){
		if((*iter).node->NodeNumber == startNumber){
			(*iter).visited = true;
		}
	}

	//find start-node and start assessment (attack cost & risk)
	nodeList inode = findNode(G, startNumber);
	
	parms_id_type cost_parms_id = inode.node->Weight.parms_id();
        eval.mod_switch_to_inplace(cost, cost_parms_id);
	
	LweSample *T = new_gate_bootstrapping_ciphertext(EK->params);	// a variable for check paths are real.
	bootsCONSTANT(T, 1, EK);
	vector<int> path;	//vector to store path information
	probe(G, cost, risk, inode, T, path, destNumber, EK, PK, eval,relin_keys, context, secret_key);		//PK & secret key are only used for check result(not in assessment process)
	delete_gate_bootstrapping_ciphertext(T);
}

///////////////////////////////////////////////////////////////////////////////

//find a length of the shortest path
void probeMinCut(struct Graph& G, struct nodeList& N, vector<int> path, int &Length, int dest, int &tryCnt, const TFheGateBootstrappingCloudKeySet* EK){
	tryCnt ++;
	int gS = G.node->size();
	if((Length == 1000000) && tryCnt >3000*gS){
		return;
	}	

	path.push_back(N.node->NodeNumber);
	N.visited = true;
	list<struct Neighbor>::iterator iter;

	if(path.size() > Length){
		return;
	}
	else{
		if(N.node->NodeNumber == dest){
			if(Length > path.size()){
				Length = path.size();
			}
		}
		else{
			for(iter = N.node->Neighbors->begin(); iter != N.node->Neighbors->end(); ++iter){
				list<struct nodeList>::iterator iter2;
				for(iter2 = G.node->begin(); iter2 != G.node->end(); ++iter2){
					if((*iter).NodeNumber == (*iter2).node->NodeNumber && (*iter2).visited == false){
						probeMinCut(G, (*iter2), path, Length, dest, tryCnt, EK);
						(*iter2).visited = false;
					}
				}
			}
		}	
	}
	N.visited = false;
}

//initial function to start minCut
int minCut(struct Graph& G, int startNumber, int destNumber, const TFheGateBootstrappingCloudKeySet* EK){
	int src = startNumber;
	int dst = destNumber;

	int node_size = G.node->size();
        int *dist = new int[node_size];
        for(int i=0; i<node_size; i++)  dist[i] = 1000000;

        vector<int> stack;
        dist[src] = 1;
        stack.push_back(src);
        while(stack.size()>0)
        {
                int cur_node = stack[stack.size()-1];
                stack.pop_back();
                nodeList n = findNode(G, cur_node);
                for(auto N : *(n.node->Neighbors))
                {
                        int target = N.NodeNumber;
                        if(dist[cur_node]+1<dist[target])
                        {
                                dist[target] = dist[cur_node]+1;
                                if(target!= dst)        stack.push_back(target);
                        }
                }
        }
	int value = dist[dst];
        delete(dist);
        return value;

	//old version : deprecated
	int MinLength = 1000000;                //just a large value.
	int tryCnt = 0;
	list<struct nodeList>::iterator iter;
	for(iter = G.node->begin(); iter != G.node->end(); ++iter){
		(*iter).visited = false;
	}
	for(iter = G.node->begin(); (*iter).node->NodeNumber != startNumber; ++iter);
	vector<int> P;
	probeMinCut(G, *iter, P, MinLength, destNumber, tryCnt, EK);
	return MinLength;
}

//find a length of the shortest path
void probeMinLength(struct Graph& G, struct nodeList& N, vector<int> path, int* Length, int dest, const TFheGateBootstrappingCloudKeySet* EK){
	path.push_back(N.node->NodeNumber);
	N.visited = true;
	list<struct Neighbor>::iterator iter;

	if(N.node->NodeNumber == dest){
		if(*Length > path.size()){
			*Length = path.size();
		}
	}
	else{
		for(iter = N.node->Neighbors->begin(); iter != N.node->Neighbors->end(); ++iter){
			list<struct nodeList>::iterator iter2;
			for(iter2 = G.node->begin(); iter2 != G.node->end(); ++iter2){
				if((*iter).NodeNumber == (*iter2).node->NodeNumber && (*iter2).visited == false){
					probeMinLength(G, (*iter2), path, Length, dest, EK);     
					(*iter2).visited = false;
				}
			}
		}
	}
	N.visited = false;
}


//initial function to start minCut
int minLength(struct Graph& G, int startNumber, int destNumber, const TFheGateBootstrappingCloudKeySet* EK){
	int MinLength = 1000000;                //just a large value.
	list<struct nodeList>::iterator iter;
	for(iter = G.node->begin(); iter != G.node->end(); ++iter){
		(*iter).visited = false;
	}
	for(iter = G.node->begin(); (*iter).node->NodeNumber != startNumber; ++iter);
	vector<int> P;
	probeMinLength(G, *iter, P, &MinLength, destNumber, EK);
	return MinLength;
}

//find the shotest paths between two nodes
void probeShortestPath(struct Graph& G, Ciphertext cost, Ciphertext risk, struct nodeList &N, LweSample* Tmp, vector<int> path, int dest, int shortestLength, double mpl, const TFheGateBootstrappingCloudKeySet* EK, Evaluator &eval, auto &relin_keys, std::shared_ptr<seal::SEALContext> context){
	N.visited = true;
//	std::ofstream out("mplInfo.txt", std::ios::app);
//	cout << N.node->NodeNumber << endl;
	if(N.node->user == false){
		//calculate attack cost
		eval.add_inplace(cost,N.node->Weight);
		//calculate risk
		Ciphertext Rst;
		eval.multiply(N.node->Impact,N.node->Pr,Rst);
		eval.relinearize_inplace(Rst,relin_keys);
		eval.rescale_to_next_inplace(Rst);
		parms_id_type last_parms_id = Rst.parms_id();
		Rst.scale() = pow(2.0,40);
		eval.mod_switch_to_inplace(risk, last_parms_id);
		eval.add(risk,Rst,risk);
	}
	path.push_back(N.node->NodeNumber);
	list<struct Neighbor>::iterator iter;
	if(N.node->NodeNumber == dest){
		if(path.size() == shortestLength){
//				out <<"MPL: " <<mpl <<endl;
//				out <<"path: ";
//				if(out.is_open()){
//					for(auto Path : path){
//						out <<Path <<" ";
//					}
//					out <<", attack cost: ";
//					cost.save(out);
//					out <<", risk: ";
//					risk.save(out);
//					out <<", real: ";
//					export_gate_bootstrapping_ciphertext_toStream(out, Tmp, EK->params);
//					out <<endl;
		}
	}	
	else{
		for(iter = N.node->Neighbors->begin(); iter != N.node->Neighbors->end(); ++iter){
			list<struct nodeList>::iterator iter2;
			for(iter2 = G.node->begin(); iter2 != G.node->end(); ++iter2){
				if((*iter).NodeNumber == (*iter2).node->NodeNumber && (*iter2).visited == false){
					LweSample *Temp = new_gate_bootstrapping_ciphertext(EK->params);
					bootsAND(Temp,Tmp,(*iter).T,EK);
					probeShortestPath(G, cost, risk, (*iter2), Temp, path, dest, shortestLength, mpl, EK, eval, relin_keys, context);
					(*iter2).visited = false;
				}
			}
		}
	}
	N.visited = false;
}

//initial function to start probe
void init_probeShortestPath(struct Graph& G, int startNumber, int destNumber, int shortestLength, double mpl, const TFheGateBootstrappingCloudKeySet* EK, Evaluator &eval, seal::RelinKeys& relin_keys, seal::PublicKey public_key, std::shared_ptr<seal::SEALContext> context){
	double scale = pow(2.0,40);
	CKKSEncoder encoder(context);
	Plaintext Cost,Risk;
	encoder.encode(0, scale, Cost);
	encoder.encode(0, scale, Risk);
	
	Encryptor encryptor(context, public_key);
	Ciphertext cost,risk;
	encryptor.encrypt(Cost,cost);
	encryptor.encrypt(Risk,risk);

	for(auto inode : *(G.node)){
		inode.visited = false;
	}
	
	list<struct nodeList>::iterator iter;
	for(iter = G.node->begin(); iter != G.node->end();++iter){
		if((*iter).node->NodeNumber == startNumber){
			(*iter).visited = true;
		}
	}
	
	for(auto inode : *(G.node)){
		if(inode.node->NodeNumber != startNumber){
			continue;
		}
		LweSample *T = new_gate_bootstrapping_ciphertext(EK->params);
		bootsCONSTANT(T, 1, EK);
		vector<int> path;
		
		probeShortestPath(G, cost, risk, inode, T, path, destNumber, shortestLength, mpl, EK, eval, relin_keys, context);
		delete_gate_bootstrapping_ciphertext(T);
		break;
	}
}

//find a value of mean path length
void probeMpl(struct Graph& G, struct nodeList& N, vector<int> path, int* routeNumber, int* totalHop, int dest, const TFheGateBootstrappingCloudKeySet* EK){
	path.push_back(N.node->NodeNumber);
//	printf("Node Number : %d\n",N.node->NodeNumber);
	N.visited = true;
	list<struct Neighbor>::iterator iter;
	if(N.node->NodeNumber == dest){
		*routeNumber = (*routeNumber) + 1;
		*totalHop = *totalHop + path.size();
	}
	else{
		for(iter = N.node->Neighbors->begin(); iter != N.node->Neighbors->end(); ++iter){
			list<struct nodeList>::iterator iter2;
			for(iter2 = G.node->begin(); iter2 != G.node->end(); ++iter2){
				if((*iter).NodeNumber == (*iter2).node->NodeNumber && (*iter2).visited == false){
					probeMpl(G, (*iter2), path, routeNumber, totalHop, dest, EK);
				}
			}
		}
	}
	N.visited = false;
}

//initial function to start mpl
void mpl(struct Graph& G, int startNumber, int destNumber, const TFheGateBootstrappingCloudKeySet* EK, Evaluator &eval, seal::RelinKeys& relin_keys, seal::PublicKey public_key, std::shared_ptr<seal::SEALContext> context){
	int routeNumber = 0;
	int totalHop = 0;
	list<struct nodeList>::iterator iter;
	for(iter = G.node->begin(); iter != G.node->end(); ++iter){
		(*iter).visited = false;
	}
	for(iter = G.node->begin(); (*iter).node->NodeNumber != startNumber; ++iter);
	vector<int> P;
	probeMpl(G, *iter, P, &routeNumber, &totalHop, destNumber, EK);
	double result = (double)totalHop / (double)routeNumber;
	cout <<"pathNum: " <<routeNumber <<endl;
	cout <<"totalHop: " <<totalHop <<endl;
	cout <<"MPL: " <<result <<"\t\t";

	//int shortestLength = minLength(G, startNumber, destNumber, EK);
	//init_probeShortestPath(G, startNumber, destNumber, shortestLength, result, EK, eval, relin_keys, public_key, context);	
	return;
}

//calculate degrees of all nodes
struct degree getDegree(struct Graph& G){
	struct degree V;

	// out-degree
	std::list<struct nodeList>::iterator s;
	for(s = G.node->begin(); s != G.node->end(); ++s){
		struct degInfo Dout;
		Dout.Degree = s->node->Neighbors->size();
		Dout.NodeNumber = (*s).node->NodeNumber;
		V.Vout.push_back(Dout);
	}
	int TotalNode = G.node->size();
	int OutDegree[TotalNode];
	
	for(int i = 0; i < TotalNode; i++){
		OutDegree[i] = 0;
	}
	
	// in-degree
	for(s = G.node->begin(); s != G.node->end(); ++s){
		list<struct Neighbor>::iterator Nx;
		for(Nx = (*s).node->Neighbors->begin(); Nx != (*s).node->Neighbors->end(); ++Nx){
			OutDegree[Nx->NodeNumber]++;
		}
	}

	for(int i = 0; i < TotalNode; i++){
		struct degInfo Din;
		Din.NodeNumber = i;
		Din.Degree = OutDegree[i];
		V.Vin.push_back(Din);
	}
	return V;
}

//get total degree(in-degree + out-degree) of each node
std::vector<int> totalDegree(struct degree &D){
	int L = D.Vin.size();
	int Table[L];
	for(int i = 0; i < L; i++){
		Table[i] = 0;
	}
	for(int i = 0; i < L; i++){
		Table[D.Vin[i].NodeNumber]+=D.Vin[i].Degree;
		Table[D.Vout[i].NodeNumber]+=D.Vout[i].Degree;
	}
	std::vector<int> retVec;
	for(int i = 0; i < L; i++){
		retVec.push_back(Table[i]);
	}
	return retVec;
}

//give a restriction to node which cannot be removed when pruning
void addNodeRestriction(Graph &G, int nodeNumber){
	for(list<nodeList>::iterator N = G.node->begin(); N != G.node->end(); ++N){
		if(N->node->NodeNumber == nodeNumber){
			cout << N->node->NodeNumber << endl;
			N->unchangeable = true;
		}
	}
}

//give a restriction to edge which cannot be removed when pruning
void addEdgeRestriction(Graph &G, int from, int to){
	for(list<nodeList>::iterator N = G.node->begin(); N != G.node->end(); ++N){
		if(N->node->NodeNumber == from || N->node->NodeNumber == to){
			cout << N->node->NodeNumber << endl;
			N->unchangeable = true;
		}
	}
}

//remove some nodes with small degrees and then probe again
void prune(struct Graph &G, struct degree &V, int number){
	int L = V.Vin.size();
	std::vector<int> Table = totalDegree(V);
	vector<struct degInfo> Vi;
	for(int i = 0; i < L; i++){
		struct degInfo Lm;
		Lm.NodeNumber = i;
		Lm.Degree = Table[i];
		Vi.push_back(Lm);
	}
	sort(Vi.begin(), Vi.end());
	
	vector<int> Vt;
	for(int i = 0; i < L; i++){
		if(Vi[i].NodeNumber == 0 || Vi[i].NodeNumber == G.node->size()-1){
			continue;
		}

		struct nodeList Tmp = findNode(G, Vi[i].NodeNumber);
		if(Tmp.unchangeable == false && Tmp.node->user == false){
			Vt.push_back(Vi[i].NodeNumber);
		}
		if(Vt.size() >= number){
			break;
		}
	}
/*
	for(int i=0;i<number;i++){
		cout <<Vt[i] <<"\t";
	}
*/
	list<struct nodeList>::iterator iter;
	for(list<nodeList>::iterator N = G.node->begin(); N != G.node->end(); ++N){
		int lenVt = Vt.size();
	//	printf("Current node : %d\n",(*N).node->NodeNumber);
		
		// Deleting edges.
		for(list<Neighbor>::iterator Nn = (*N).node->Neighbors->begin();Nn != (*N).node->Neighbors->end(); ++Nn){
			for(auto e : Vt){
				if(e == Nn->NodeNumber){
	//				printf("Edge to delete : -> %d\n",Nn->NodeNumber);
					(*N).node->Neighbors->erase(Nn++);
					if(Nn == (*N).node->Neighbors->end())   break;
				}
			}
			if(Nn == (*N).node->Neighbors->end())   break;
		}
		
		//Deleting nodes.
		for(auto e : Vt){
			if(e == (*N).node->NodeNumber){
	//			printf("Node to delete : -> %d\n",(*N).node->NodeNumber);
				G.node->erase(N++);
				if(N == G.node->end())   return;
			}
		}
	}
}

void PrAtkSuccessProbe(struct Graph& G, Ciphertext logPr, struct nodeList& N, LweSample* Tmp, vector<int> path, vector<Ciphertext> &pathPr, int dest, const TFheGateBootstrappingCloudKeySet* EK, Evaluator &eval, seal::RelinKeys &relin_keys, std::shared_ptr<seal::SEALContext> context, seal::SecretKey secret_key){
//// path is a vector for test ////
//// secret key is also only used in check the result ////
	
//	cout << N.node->NodeNumber << endl;
//	std::ofstream out("probabilityInfo.txt", std::ios::app);
	if(N.node->user == false){
		eval.add_inplace(logPr,N.node->logPr);
        }
//	path.push_back(N.node->NodeNumber);
	N.visited = true;
	list<struct Neighbor>::iterator iter;

	if(N.node->NodeNumber == dest){
		pathPr.push_back(logPr);
/*
		out <<"path: ";
		for(auto P : path){
			out << P << " ";
		}
		out << endl;
		out <<"independent probabilty: ";
		logpr.save(out);
		out <<", real: ";
		export_gate_bootstrapping_ciphertext_toStream(out, Tmp, EK->params);
		out <<endl;
*/

/*
		//check path
		cout <<"path: ";
                for(auto P : path){
                        cout << P << " ";
                }
		cout <<endl;
*/
/*
 		//check log of probability
		CKKSEncoder encoder(context);	
		Decryptor decryptor(context, secret_key);
		Plaintext Plain_result;
		decryptor.decrypt(logPr, Plain_result);
		vector<double> Plain_result_decode;
		encoder.decode(Plain_result, Plain_result_decode);
		cout << "logPr: " <<Plain_result_decode[0] <<endl;
*/
		return;
	}
	else{
		for(iter = N.node->Neighbors->begin(); iter != N.node->Neighbors->end(); ++iter){
			list<struct nodeList>::iterator iter2;
				for(iter2 = G.node->begin(); iter2 != G.node->end(); ++iter2){
					if((*iter).NodeNumber == (*iter2).node->NodeNumber && (*iter2).visited == false){
						LweSample *Temp = new_gate_bootstrapping_ciphertext(EK->params);
						bootsAND(Temp,Tmp,(*iter).T,EK);
						PrAtkSuccessProbe(G, logPr, (*iter2), Tmp, path, pathPr, dest, EK, eval, relin_keys, context, secret_key);
						(*iter2).visited = false;
					}
				}
		}
	}
	N.visited = false;
}

void PrAtkSuccess(struct Graph& G, int startNumber, int destNumber, const TFheGateBootstrappingCloudKeySet* EK, const TFheGateBootstrappingSecretKeySet *PK, Evaluator &eval, seal::RelinKeys& relin_keys, seal::PublicKey public_key, std::shared_ptr<seal::SEALContext> context, seal::SecretKey secret_key){
	double scale = pow(2.0,40);
	CKKSEncoder encoder(context);
	Plaintext LogPr;
        encoder.encode(0, scale, LogPr);

	Encryptor encryptor(context, public_key);
	Ciphertext logPr;
	encryptor.encrypt(LogPr,logPr);

	for(auto inode : *(G.node)){
		inode.visited = false;
	}
	
	list<struct nodeList>::iterator iter;
	for(iter = G.node->begin(); iter != G.node->end();++iter){
		if((*iter).node->NodeNumber == startNumber){
			(*iter).visited = true;
		}	
	}

	for(auto inode : *(G.node)){
		if(inode.node->NodeNumber != startNumber) continue;
		LweSample *T = new_gate_bootstrapping_ciphertext(EK->params);
		bootsCONSTANT(T, 1, EK);
		vector<int> P;	//vector for debugging
		vector<Ciphertext> pathPr;
		PrAtkSuccessProbe(G, logPr, inode, T, P, pathPr, destNumber, EK,eval,relin_keys, context, secret_key);

		Plaintext ResultPr;
		encoder.encode(0,scale,ResultPr);
		Ciphertext resultPr;
		encryptor.encrypt(ResultPr, resultPr);
		Decryptor decryptor(context, secret_key);

		int size = pathPr.size();
		for(int i=0;i<size;i++){

		/*
			//test
			Plaintext Test_result;
        	        decryptor.decrypt(pathPr[i], Test_result);
                	vector<double> Test_result_decode;
	                encoder.decode(Test_result, Test_result_decode);
	                cout <<"log(pr): " <<Test_result_decode[0] <<endl;
		*/

			Plaintext Temp0,Temp1,Temp2,Temp3,Temp4, Temp5, Temp6, Temp7, Temp8, Temp9, Temp10;
			encoder.encode(1, scale, Temp0);
			encoder.encode(1, scale, Temp1);
			encoder.encode(0.5, scale, Temp2);
			encoder.encode(0.1666, scale, Temp3);
			encoder.encode(0.04166, scale, Temp4);
			encoder.encode(0.00833, scale, Temp5);
			encoder.encode(0.001388, scale, Temp6);
			encoder.encode(0.0001984, scale, Temp7);
			encoder.encode(0.0000248, scale, Temp8);
			encoder.encode(0.00000276, scale, Temp9);
			encoder.encode(0.000000276, scale, Temp10);
			//coefficient values of Taylor expansion

			Ciphertext temp0, temp1, temp2, temp3, temp4, temp5, temp6, temp7, temp8, temp9, temp10, temp, temp_a, temp_b;
			encryptor.encrypt(Temp0, temp0);
			encryptor.encrypt(Temp1, temp1);
			encryptor.encrypt(Temp2, temp2);
			encryptor.encrypt(Temp3, temp3);
			encryptor.encrypt(Temp4, temp4);
			encryptor.encrypt(Temp5, temp5);
			encryptor.encrypt(Temp6, temp6);
			encryptor.encrypt(Temp7, temp7);
			encryptor.encrypt(Temp8, temp8);
			encryptor.encrypt(Temp9, temp9);
			encryptor.encrypt(Temp10, temp10);

//			cout <<"coeff: " <<context->get_context_data(temp1.parms_id())->chain_index() <<endl;
//			cout <<"initial: " <<context->get_context_data(pathPr[1].parms_id())->chain_index() <<endl;

			//1st term
			eval.multiply_inplace(temp1, pathPr[i]);
			eval.relinearize_inplace(temp1, relin_keys);
			eval.rescale_to_next_inplace(temp1);
			temp1.scale() = pow(2.0,40);

			//2nd term
			eval.square(pathPr[i], temp);
			eval.relinearize_inplace(temp, relin_keys);
			eval.rescale_to_next_inplace(temp);

			parms_id_type last_parms_id = temp.parms_id();
			temp.scale() = pow(2.0,40);
			eval.mod_switch_to_inplace(temp2, last_parms_id);
			eval.multiply_inplace(temp2, temp);
			eval.relinearize_inplace(temp2, relin_keys);
			eval.rescale_to_next_inplace(temp2);
			temp2.scale() = pow(2.0,40);

			//3rd term
			eval.multiply_inplace(temp3, pathPr[i]);
			eval.relinearize_inplace(temp3, relin_keys);
			eval.rescale_to_next_inplace(temp3);
			temp3.scale() = pow(2.0,40);
			
			eval.multiply_inplace(temp3, temp);
			eval.relinearize_inplace(temp3, relin_keys);
			eval.rescale_to_next_inplace(temp3);
			temp3.scale() = pow(2.0,40);

			//4th term
			eval.square(temp, temp_a);
			eval.relinearize_inplace(temp_a, relin_keys);
                        eval.rescale_to_next_inplace(temp_a);

			last_parms_id = temp_a.parms_id();
                        temp_a.scale() = pow(2.0,40);
                        eval.mod_switch_to_inplace(temp4, last_parms_id);
                        eval.multiply_inplace(temp4, temp_a);
                        eval.relinearize_inplace(temp4, relin_keys);
                        eval.rescale_to_next_inplace(temp4);
                        temp4.scale() = pow(2.0,40);

			//5th term
			eval.multiply_inplace(temp5, pathPr[i]);
			eval.relinearize_inplace(temp5, relin_keys);
                        eval.rescale_to_next_inplace(temp5);
                        temp5.scale() = pow(2.0,40);

			eval.mod_switch_to_inplace(temp5, last_parms_id);
                        eval.multiply_inplace(temp5, temp_a);
                        eval.relinearize_inplace(temp5, relin_keys);
                        eval.rescale_to_next_inplace(temp5);
                        temp5.scale() = pow(2.0,40);

			//6th term
			last_parms_id = temp.parms_id();
                        temp.scale() = pow(2.0,40);
                        eval.mod_switch_to_inplace(temp6, last_parms_id);
                        eval.multiply_inplace(temp6, temp);
                        eval.relinearize_inplace(temp6, relin_keys);
                        eval.rescale_to_next_inplace(temp6);
                        temp6.scale() = pow(2.0,40);

			last_parms_id = temp_a.parms_id();
                        temp_a.scale() = pow(2.0,40);
                        eval.mod_switch_to_inplace(temp6, last_parms_id);
                        eval.multiply_inplace(temp6, temp_a);
                        eval.relinearize_inplace(temp6, relin_keys);
                        eval.rescale_to_next_inplace(temp6);
                        temp6.scale() = pow(2.0,40);

			//7th term
			eval.multiply_inplace(temp7, pathPr[i]);
                        eval.relinearize_inplace(temp7, relin_keys);
                        eval.rescale_to_next_inplace(temp7);
                        temp7.scale() = pow(2.0,40);

			last_parms_id = temp.parms_id();
                        temp.scale() = pow(2.0,40);
                        eval.mod_switch_to_inplace(temp7, last_parms_id);
                        eval.multiply_inplace(temp7, temp);
                        eval.relinearize_inplace(temp7, relin_keys);
                        eval.rescale_to_next_inplace(temp7);
                        temp7.scale() = pow(2.0,40);

                        last_parms_id = temp_a.parms_id();
                        temp_a.scale() = pow(2.0,40);
                        eval.mod_switch_to_inplace(temp7, last_parms_id);
                        eval.multiply_inplace(temp7, temp_a);
                        eval.relinearize_inplace(temp7, relin_keys);
                        eval.rescale_to_next_inplace(temp7);
                        temp7.scale() = pow(2.0,40);

			//8th term
			eval.square(temp_a, temp_b);
                        eval.relinearize_inplace(temp_b, relin_keys);
                        eval.rescale_to_next_inplace(temp_b);

                        last_parms_id = temp_b.parms_id();
                        temp_b.scale() = pow(2.0,40);
                        eval.mod_switch_to_inplace(temp8, last_parms_id);
                        eval.multiply_inplace(temp8, temp_b);
                        eval.relinearize_inplace(temp8, relin_keys);
                        eval.rescale_to_next_inplace(temp8);
                        temp8.scale() = pow(2.0,40);

			//9th term
			eval.multiply_inplace(temp9, pathPr[i]);
                        eval.relinearize_inplace(temp9, relin_keys);
                        eval.rescale_to_next_inplace(temp9);
                        temp9.scale() = pow(2.0,40);

			eval.mod_switch_to_inplace(temp9, last_parms_id);
                        eval.multiply_inplace(temp9, temp_b);
                        eval.relinearize_inplace(temp9, relin_keys);
                        eval.rescale_to_next_inplace(temp9);
                        temp9.scale() = pow(2.0,40);

			//10th term
			last_parms_id = temp.parms_id();
                        temp.scale() = pow(2.0,40);
                        eval.mod_switch_to_inplace(temp10, last_parms_id);
                        eval.multiply_inplace(temp10, temp);
                        eval.relinearize_inplace(temp10, relin_keys);
                        eval.rescale_to_next_inplace(temp10);
                        temp10.scale() = pow(2.0,40);

			last_parms_id = temp_b.parms_id();
                        temp_b.scale() = pow(2.0,40);
                        eval.mod_switch_to_inplace(temp10, last_parms_id);
                        eval.multiply_inplace(temp10, temp_b);
                        eval.relinearize_inplace(temp10, relin_keys);
                        eval.rescale_to_next_inplace(temp10);
                        temp10.scale() = pow(2.0,40);


			last_parms_id = temp10.parms_id();
			eval.mod_switch_to_inplace(temp0, last_parms_id);
			eval.mod_switch_to_inplace(temp1, last_parms_id);
			eval.mod_switch_to_inplace(temp2, last_parms_id);
			eval.mod_switch_to_inplace(temp3, last_parms_id);
			eval.mod_switch_to_inplace(temp4, last_parms_id);
			eval.mod_switch_to_inplace(temp5, last_parms_id);
			eval.mod_switch_to_inplace(temp6, last_parms_id);
			eval.mod_switch_to_inplace(temp7, last_parms_id);
			eval.mod_switch_to_inplace(temp8, last_parms_id);
			eval.mod_switch_to_inplace(temp9, last_parms_id);

			eval.add_inplace(temp0, temp1);
			eval.add_inplace(temp0, temp2);
			eval.add_inplace(temp0, temp3);
			eval.add_inplace(temp0, temp4);
			eval.add_inplace(temp0, temp5);
			eval.add_inplace(temp0, temp6);
			eval.add_inplace(temp0, temp7);
			eval.add_inplace(temp0, temp8);
			eval.add_inplace(temp0, temp9);
			eval.add_inplace(temp0, temp10);

		/*
			//test
			Plaintext Test_result2;
	                decryptor.decrypt(temp0, Test_result2);
        	        vector<double> Test_result_decode2;
                	encoder.decode(Test_result2, Test_result_decode2);
	                cout << "pr: " <<Test_result_decode2[0] <<endl;
		*/

	//secong appproximation
			Plaintext secondTemp1, secondTemp2, secondTemp3, secondTemp4, secondTemp5, secondTemp6, secondTemp7, secondTemp8, secondTemp9, secondTemp10;
                        encoder.encode(-1, scale, secondTemp1);
                        encoder.encode(-0.5, scale, secondTemp2);
                        encoder.encode(-0.333333, scale, secondTemp3);
			encoder.encode(-0.25, scale, secondTemp4);
			encoder.encode(-0.2, scale, secondTemp5);
			encoder.encode(-0.16666, scale, secondTemp6);
			encoder.encode(-0.1428, scale, secondTemp7);
			encoder.encode(-0.125, scale, secondTemp8);
			encoder.encode(-0.1111, scale, secondTemp9);
			encoder.encode(-0.1, scale, secondTemp10);

                        Ciphertext secondtemp1, secondtemp2, secondtemp3, secondtemp4, secondtemp5, secondtemp6, secondtemp7, secondtemp8, secondtemp9, secondtemp10, secondtemp, secondtemp_a, secondtemp_b;

			encryptor.encrypt(secondTemp1, secondtemp1);
                        encryptor.encrypt(secondTemp2, secondtemp2);
                        encryptor.encrypt(secondTemp3, secondtemp3);
			encryptor.encrypt(secondTemp4, secondtemp4);
			encryptor.encrypt(secondTemp5, secondtemp5);
			encryptor.encrypt(secondTemp6, secondtemp6);
			encryptor.encrypt(secondTemp7, secondtemp7);
			encryptor.encrypt(secondTemp8, secondtemp8);
			encryptor.encrypt(secondTemp9, secondtemp9);
			encryptor.encrypt(secondTemp10, secondtemp10);

			//mult x
			eval.mod_switch_to_inplace(secondtemp1, last_parms_id);
			eval.mod_switch_to_inplace(secondtemp3, last_parms_id);
			eval.mod_switch_to_inplace(secondtemp5, last_parms_id);
			eval.mod_switch_to_inplace(secondtemp7, last_parms_id);
			eval.mod_switch_to_inplace(secondtemp9, last_parms_id);
			eval.multiply_inplace(secondtemp1, temp0);
			eval.multiply_inplace(secondtemp3, temp0);
			eval.multiply_inplace(secondtemp5, temp0);
			eval.multiply_inplace(secondtemp7, temp0);
			eval.multiply_inplace(secondtemp9, temp0);
			eval.relinearize_inplace(secondtemp1, relin_keys);
			eval.relinearize_inplace(secondtemp3, relin_keys);
			eval.relinearize_inplace(secondtemp5, relin_keys);
			eval.relinearize_inplace(secondtemp7, relin_keys);
			eval.relinearize_inplace(secondtemp9, relin_keys);
			eval.rescale_to_next_inplace(secondtemp1);
			eval.rescale_to_next_inplace(secondtemp3);
			eval.rescale_to_next_inplace(secondtemp5);
			eval.rescale_to_next_inplace(secondtemp7);
			eval.rescale_to_next_inplace(secondtemp8);
			secondtemp1.scale() = pow(2.0,40);
			secondtemp3.scale() = pow(2.0,40);
			secondtemp5.scale() = pow(2.0,40);
			secondtemp7.scale() = pow(2.0,40);
			secondtemp9.scale() = pow(2.0,40);

			//mult x^2
			eval.square(temp0, secondtemp);
			eval.relinearize_inplace(secondtemp, relin_keys);
			eval.rescale_to_next_inplace(secondtemp);
			secondtemp.scale() = pow(2.0, 40);
			last_parms_id = secondtemp.parms_id();
                        eval.mod_switch_to_inplace(secondtemp2, last_parms_id);
                        eval.mod_switch_to_inplace(secondtemp3, last_parms_id);
			eval.mod_switch_to_inplace(secondtemp6, last_parms_id);
			eval.mod_switch_to_inplace(secondtemp7, last_parms_id);
			eval.mod_switch_to_inplace(secondtemp10, last_parms_id);
			eval.multiply_inplace(secondtemp2, secondtemp);
			eval.multiply_inplace(secondtemp3, secondtemp);
			eval.multiply_inplace(secondtemp6, secondtemp);
			eval.multiply_inplace(secondtemp7, secondtemp);
			eval.multiply_inplace(secondtemp10, secondtemp);
			eval.relinearize_inplace(secondtemp2, relin_keys);
			eval.relinearize_inplace(secondtemp3, relin_keys);
			eval.relinearize_inplace(secondtemp6, relin_keys);
			eval.relinearize_inplace(secondtemp7, relin_keys);
			eval.relinearize_inplace(secondtemp10, relin_keys);
			eval.rescale_to_next_inplace(secondtemp2);
			eval.rescale_to_next_inplace(secondtemp3);
			eval.rescale_to_next_inplace(secondtemp6);
			eval.rescale_to_next_inplace(secondtemp7);
			eval.rescale_to_next_inplace(secondtemp10);
			secondtemp2.scale() = pow(2.0,40);
			secondtemp3.scale() = pow(2.0,40);
			secondtemp6.scale() = pow(2.0,40);
			secondtemp7.scale() = pow(2.0,40);
			secondtemp10.scale() = pow(2.0,40);

			//mult x^4
			eval.square(secondtemp, secondtemp_a);
                        eval.relinearize_inplace(secondtemp_a, relin_keys);
                        eval.rescale_to_next_inplace(secondtemp_a);
                        secondtemp_a.scale() = pow(2.0, 40);
                        last_parms_id = secondtemp_a.parms_id();
                        eval.mod_switch_to_inplace(secondtemp4, last_parms_id);
                        eval.mod_switch_to_inplace(secondtemp5, last_parms_id);
                        eval.mod_switch_to_inplace(secondtemp6, last_parms_id);
                        eval.mod_switch_to_inplace(secondtemp7, last_parms_id);

			eval.multiply_inplace(secondtemp4, secondtemp_a);
                        eval.multiply_inplace(secondtemp5, secondtemp_a);
                        eval.multiply_inplace(secondtemp6, secondtemp_a);
                        eval.multiply_inplace(secondtemp7, secondtemp_a);

			eval.relinearize_inplace(secondtemp4, relin_keys);
                        eval.relinearize_inplace(secondtemp5, relin_keys);
                        eval.relinearize_inplace(secondtemp6, relin_keys);
                        eval.relinearize_inplace(secondtemp7, relin_keys);
                        eval.rescale_to_next_inplace(secondtemp4);
                        eval.rescale_to_next_inplace(secondtemp5);
                        eval.rescale_to_next_inplace(secondtemp6);
                        eval.rescale_to_next_inplace(secondtemp7);
                        secondtemp4.scale() = pow(2.0,40);
                        secondtemp5.scale() = pow(2.0,40);
                        secondtemp6.scale() = pow(2.0,40);
                        secondtemp7.scale() = pow(2.0,40);


			//mult x^8
			eval.square(secondtemp_a, secondtemp_b);
                        eval.relinearize_inplace(secondtemp_b, relin_keys);
                        eval.rescale_to_next_inplace(secondtemp_b);
                        secondtemp_b.scale() = pow(2.0, 40);
                        last_parms_id = secondtemp_b.parms_id();
                        eval.mod_switch_to_inplace(secondtemp8, last_parms_id);
                        eval.mod_switch_to_inplace(secondtemp9, last_parms_id);
                        eval.mod_switch_to_inplace(secondtemp10, last_parms_id);
                        eval.multiply_inplace(secondtemp8, secondtemp_b);
                        eval.multiply_inplace(secondtemp9, secondtemp_b);
                        eval.multiply_inplace(secondtemp10, secondtemp_b);
                        eval.relinearize_inplace(secondtemp8, relin_keys);
                        eval.relinearize_inplace(secondtemp9, relin_keys);
                        eval.relinearize_inplace(secondtemp10, relin_keys);
                        eval.rescale_to_next_inplace(secondtemp8);
                        eval.rescale_to_next_inplace(secondtemp9);
                        eval.rescale_to_next_inplace(secondtemp10);
                        secondtemp8.scale() = pow(2.0,40);
                        secondtemp9.scale() = pow(2.0,40);
                        secondtemp10.scale() = pow(2.0,40);
			
			//add all
			last_parms_id = secondtemp10.parms_id();
			eval.mod_switch_to_inplace(secondtemp1, last_parms_id);
			eval.mod_switch_to_inplace(secondtemp2, last_parms_id);
			eval.mod_switch_to_inplace(secondtemp3, last_parms_id);
			eval.mod_switch_to_inplace(secondtemp4, last_parms_id);
			eval.mod_switch_to_inplace(secondtemp5, last_parms_id);
			eval.mod_switch_to_inplace(secondtemp6, last_parms_id);
			eval.mod_switch_to_inplace(secondtemp7, last_parms_id);
			eval.mod_switch_to_inplace(secondtemp8, last_parms_id);
			eval.mod_switch_to_inplace(secondtemp9, last_parms_id);
			eval.add_inplace(secondtemp1, secondtemp2);
			eval.add_inplace(secondtemp1, secondtemp3);
			eval.add_inplace(secondtemp1, secondtemp4);
			eval.add_inplace(secondtemp1, secondtemp5);
			eval.add_inplace(secondtemp1, secondtemp6);
			eval.add_inplace(secondtemp1, secondtemp7);
			eval.add_inplace(secondtemp1, secondtemp8);
			eval.add_inplace(secondtemp1, secondtemp9);
			eval.add_inplace(secondtemp1, secondtemp10);
		/*
			//test
                        Plaintext Test_result3;
                        decryptor.decrypt(secondtemp1, Test_result3);
                        vector<double> Test_result_decode3;
                        encoder.decode(Test_result3, Test_result_decode3);
                        cout << "log(1-pr): " <<Test_result_decode3[0] <<endl;
		*/
			last_parms_id = secondtemp1.parms_id();
			eval.mod_switch_to_inplace(resultPr, last_parms_id);
			eval.add_inplace(resultPr, secondtemp1);	
		}
		/*
			//test
                        Plaintext FinalResult;
                        decryptor.decrypt(finalResult, FinalResult);
                        vector<double> FinalResult_decode;
                        encoder.decode(FinalResult, FinalResult_decode);
                        cout << "result: " <<FinalResult_decode[0] <<endl;
		*/
		delete_gate_bootstrapping_ciphertext(T);
		break;
	}
//	eval.sub(base,result,result);
	return;
}

void levelUpSEAL(Ciphertext &pr, Evaluator &eval, seal::PublicKey public_key, seal::RelinKeys &relin_keys, std::shared_ptr<seal::SEALContext> context, seal::SecretKey secret_key){
        double scale = pow(2.0,40);
        CKKSEncoder encoder(context);
        Encryptor encryptor(context, public_key);
	Decryptor decryptor(context, secret_key);
	Plaintext temp_result;

	decryptor.decrypt(pr, temp_result);
	vector<double> tempResult;
	encoder.decode(temp_result, tempResult);
//	cout <<"temp result: " <<tempResult[0] <<endl;

        encoder.encode(tempResult[0],scale,temp_result);
	encryptor.encrypt(temp_result, pr);
}

void cumulPrAtkSuccessProbe(struct Graph& G, struct nodeList& N, vector<int> &inDegree, queue<int> &searchList, vector<Ciphertext> &tempNodePr, vector<Ciphertext> &finalNodePr, int source, Evaluator &eval, seal::PublicKey public_key, seal::RelinKeys &relin_keys, std::shared_ptr<seal::SEALContext> context, seal::SecretKey secret_key){
	
//TODO	
	int graphSize = G.node->size();
        CKKSEncoder encoder(context);
        double scale = pow(2.0,40);
        Encryptor encryptor(context, public_key);

	int calFin[graphSize] = {0,};

	while(searchList.empty() != true){
		int current = searchList.front();
	//	cout <<"current node number: " <<current <<endl;
		searchList.pop();
		struct nodeList currentNode = findNode(G,current);
		if(calFin[current] == 0 && inDegree[current] == 0){	
			calFin[current] = 1;
			if(current != source){
	//			cout <<"calculate finalNodePr" <<endl;
				Plaintext OrPr;
	                        Ciphertext orPr;
	                        encoder.encode(1,scale,OrPr);
	                        encryptor.encrypt(OrPr,orPr);
	                        eval.sub_inplace(orPr,tempNodePr[current]);
	                        eval.multiply_inplace(finalNodePr[current], orPr);
	                        eval.relinearize_inplace(finalNodePr[current], relin_keys);
	                        eval.rescale_to_next_inplace(finalNodePr[current]);
	                        finalNodePr[current].scale() = pow(2.0,40);			
				levelUpSEAL(finalNodePr[current], eval, public_key, relin_keys, context, secret_key);
			}
			else{
	//			cout <<"It's start point" <<endl;
			}

			Plaintext Temp;
			Ciphertext temp;
			encoder.encode(1,scale,Temp);
			encryptor.encrypt(Temp, temp);
			eval.sub_inplace(temp, finalNodePr[current]);

	//		cout <<"calculate tempNodePr" <<endl;
			list <struct Neighbor>::iterator iter;
			for(iter = currentNode.node->Neighbors->begin(); iter != currentNode.node->Neighbors->end(); iter++){
				int next = (*iter).NodeNumber;
				inDegree[next]--;
				searchList.push(next);
				eval.multiply_inplace(tempNodePr[next], temp);
				eval.relinearize_inplace(tempNodePr[next],relin_keys);
				eval.rescale_to_next_inplace(tempNodePr[next]);
				tempNodePr[next].scale() = pow(2.0,40);
				levelUpSEAL(tempNodePr[next], eval, public_key, relin_keys, context, secret_key);
			}
		}
	}

	return;
}


void cumulPrAtkSuccess(struct Graph& G, int startNumber, Evaluator &eval, seal::RelinKeys& relin_keys, seal::PublicKey public_key, std::shared_ptr<seal::SEALContext> context, seal::SecretKey secret_key){
	int graphSize = G.node->size();
	double scale = pow(2.0,40);
	CKKSEncoder encoder(context);
	Encryptor encryptor(context, public_key);

	struct degree deg = getDegree(G);
	vector<int> inDegree;
	for(int i=0;i<graphSize;i++){
		inDegree.push_back(deg.Vin[i].Degree);
	}
	inDegree[startNumber] = 0;

	Plaintext Init;
	Ciphertext init;
	encoder.encode(1,scale,Init);
	encryptor.encrypt(Init, init);

	vector<Ciphertext> tempNodePr;
	for(int i=0;i<graphSize;i++){
		tempNodePr.push_back(init);
	}

	vector<Ciphertext> finalNodePr;
	for(int i=0;i<graphSize;i++){
		struct nodeList targetNode = findNode(G,i);
		finalNodePr.push_back(targetNode.node->Pr);	
	}

	queue<int> searchList;
	searchList.push(startNumber);
	for(auto inode : *(G.node)){
                if(inode.node->NodeNumber != startNumber){
                        continue;
                }

		cumulPrAtkSuccessProbe(G, inode, inDegree, searchList, tempNodePr, finalNodePr, startNumber, eval, public_key, relin_keys, context, secret_key);

		std::ofstream out("cumulative_probability.txt", std::ios::app);
		for(int i=0;i<graphSize;i++){
			out<<"node number: " <<i <<", cumulative probability: ";
			finalNodePr[i].save(out);
			out <<endl;
		}
	/*
		//test result
		for(int i=0;i<graphSize;i++){	
        		Decryptor decryptor(context, secret_key);
		        Plaintext temp_result;

		        decryptor.decrypt(finalNodePr[i], temp_result);
		        vector<double> tempResult;
		        encoder.decode(temp_result, tempResult);
		        cout <<"final result-" <<i <<": " <<tempResult[0] <<endl;
		}
	*/
		break;
	}
}
void diffRiskreturnOnInvestment(struct Graph &G, Ciphertext risk, struct nodeList &N, vector<int> path, int dest, vector<Ciphertext> &diffRisk, const TFheGateBootstrappingCloudKeySet* EK, const TFheGateBootstrappingSecretKeySet *PK, Evaluator &eval, seal::RelinKeys& relin_keys, seal::PublicKey public_key, std::shared_ptr<seal::SEALContext> context, seal::SecretKey secret_key){
	int graphSize = G.node->size();
	CKKSEncoder encoder(context);
	double scale = pow(2.0,40);
	Encryptor encryptor(context, public_key);

	Ciphertext temp;
        Plaintext Temp;
        encoder.encode(0, scale, Temp);
        encryptor.encrypt(Temp,temp);

	for(int i=0;i<graphSize;i++){
		diffRisk.push_back(temp);
	}
	
	N.visited = true;
	if(N.node->user == false){
		//calculate risk
		Ciphertext Rst;
		eval.multiply(N.node->Impact,N.node->Pr,Rst);
		eval.relinearize_inplace(Rst,relin_keys);
		eval.rescale_to_next_inplace(Rst);
		parms_id_type last_parms_id = Rst.parms_id();
		Rst.scale() = pow(2.0,40);
		eval.mod_switch_to_inplace(risk, last_parms_id);
		eval.add_inplace(risk,Rst);
	}
	path.push_back(N.node->NodeNumber);
	list<struct Neighbor>::iterator iter;
	if(N.node->NodeNumber == dest){
//		cout <<"path: ";
		for(auto Path : path){
//			cout <<Path <<" ";
			parms_id_type last_parms_id = risk.parms_id();
			risk.scale() = pow(2.0,40);
			eval.mod_switch_to_inplace(diffRisk[Path], last_parms_id);
			eval.add_inplace(diffRisk[Path], risk);
		}
	}
	else{
		for(iter = N.node->Neighbors->begin(); iter != N.node->Neighbors->end(); ++iter){
			list<struct nodeList>::iterator iter2;
			for(iter2 = G.node->begin(); iter2 != G.node->end(); ++iter2){
				if((*iter).NodeNumber == (*iter2).node->NodeNumber && (*iter2).visited == false){
					diffRiskreturnOnInvestment(G, risk, (*iter2), path, dest, diffRisk, EK, PK, eval, relin_keys, public_key, context, secret_key);
					(*iter2).visited = false;
				}
			}
		}
	}
	N.visited = false;
}

//function to calculate return on investment
void returnInvestment(struct Graph& G, int startNumber, int destNumber, int target, const TFheGateBootstrappingCloudKeySet* EK, const TFheGateBootstrappingSecretKeySet *PK, Evaluator &eval, seal::RelinKeys& relin_keys, seal::PublicKey public_key, std::shared_ptr<seal::SEALContext> context, seal::SecretKey secret_key){
	int graphSize = G.node->size();
	double scale = pow(2.0,40);
	CKKSEncoder encoder(context);
	Plaintext Risk;
	encoder.encode(0, scale, Risk);
	
	Encryptor encryptor(context, public_key);
	Ciphertext risk;
	encryptor.encrypt(Risk,risk);

	for(auto inode : *(G.node)){
		inode.visited = false;
	}

	list<struct nodeList>::iterator iter;
	for(iter = G.node->begin(); iter != G.node->end();++iter){
		if((*iter).node->NodeNumber == startNumber){
			(*iter).visited = true;
		}
	}

	for(auto inode : *(G.node)){
		if(inode.node->NodeNumber != startNumber){
			continue;
		}
		vector<int> path;
		vector<Ciphertext> diffRisk;
		diffRiskreturnOnInvestment(G, risk, inode, path, destNumber, diffRisk, EK, PK, eval, relin_keys, public_key, context, secret_key);
		
		
		for(int i=0;i<graphSize;i++){
			if(i == target){
				struct nodeList targetNode;
				targetNode = findNode(G,i);
				parms_id_type last_parms_id = diffRisk[i].parms_id();
				diffRisk[i].scale() = pow(2.0,40);
				eval.mod_switch_to_inplace(targetNode.node->Patch, last_parms_id);
				eval.mod_switch_to_inplace(targetNode.node->inversePatch, last_parms_id);
				eval.sub_inplace(diffRisk[i], targetNode.node->Patch);
				eval.multiply_inplace(diffRisk[i], targetNode.node->inversePatch);
			/*	
				std::ofstream out("return_on_investment_Info.txt", std::ios::app);
				if(out.is_open()){
					out <<"Node " <<i <<": ";
					diffRisk[i].save(out);
					out <<endl;
				}
			*/
			/*
	                	//check result        
				if(targetNode.node->user == false){
					Decryptor decryptor(context, secret_key);
					Plaintext result_plaintext;
					decryptor.decrypt(diffRisk[i], result_plaintext);
					vector<double> resultInvest;
					encoder.decode(result_plaintext, resultInvest);
						cout <<"Node " <<i <<": " <<resultInvest[0] <<endl;
				}
			*/
			}
		}		
		break;
	}
}


//// fuctions for generatig GSM using information recieved from client////
Ciphertext summation(std::shared_ptr<seal::SEALContext> &context, CKKSEncoder &ckks_encoder, Ciphertext c, GaloisKeys &gal_keys, Evaluator &evaluator)
{
        int logK = 0;
        int k = ckks_encoder.slot_count();
        while(k>1)
        {
                logK++;
                k/=2;
        }
        int rot = 1;
        Ciphertext dest;
        for(int i=0;i<logK-1;i++)
        {
                evaluator.rotate_vector(c, rot, gal_keys, dest);
                evaluator.add_inplace(c, dest);
                rot*=2;
        }
        return c;
}

void processQuery(Graph &G, int NID, std::shared_ptr<seal::SEALContext> context, GaloisKeys &gal_keys, Evaluator &evaluator, seal::RelinKeys &relin_keys)
{
        Ciphertext column;
        Ciphertext queried_vector; // pairwise product vector with queryProduct, cloumn. We make queried_value with this. 
        Ciphertext queryProduct;

        //load queryProduct ( vector to product with value column to get the value of target record)
        std::ifstream ctresult("query/queryProduct"+to_string(NID),std::ifstream::binary);
        queryProduct.load(context,ctresult);
        ctresult.close();
        CKKSEncoder encoder(context);
        Plaintext R;
        std::vector<double> RR;

        std::vector<std::vector<double>> table;
        for(auto N : *(G.node))
        {
                //Bring OS table from file
                if(N.node->NodeNumber == NID)
                {
                        std::ifstream input("table/OSTable");
                        std::string line;
                        while(std::getline(input,line))
                        {
                                stringstream ss(line);
                                std::string vulnerability;
                                vector<double> vulnerabilites;
                                while(getline(ss,vulnerability,' '))
                                {
                                        vulnerabilites.push_back(atof(vulnerability.c_str()));
                                }
				if(table.size()==0) //Initial stage : build first row.
                                {
                                        for(auto e : vulnerabilites)
                                        {
                                                vector<double> T;
                                                T.push_back(e);
                                                table.push_back(T);
                                        }
                                }
                                else
                                {
                                        int L = table.size();
                                        for(int i=0; i<L;i++)
                                        {
                                                table[i].push_back(vulnerabilites[i]);
                                        }
                                }
                        }
                        for(int i = 0; i < 6; i++)
                        {
                                double scale = pow(2.0,40);
                                CKKSEncoder encoder(context);
                                Plaintext pt;
                                vector<double> T = table[i+1];
                                encoder.encode(T,scale,pt);
                                //Vector pairwise product

                                evaluator.multiply_plain(queryProduct,pt,queried_vector);
                                //evaluator.relinearize_inplace(queried_vector,relin_keys); 
                                //evaluator.rescale_to_next_inplace(queried_vector);

                                Ciphertext queried_value = summation(context, encoder, queried_vector, gal_keys, evaluator);
                                evaluator.relinearize_inplace(queried_value,relin_keys);
                                evaluator.rescale_to_next_inplace(queried_value);
                                queried_value.scale() = pow(2.0,40);

				if(i==0)        N.node->Weight = queried_value;
                                if(i==1)        N.node->Impact = queried_value;
                                if(i==2)        N.node->Pr = queried_value;
                                if(i==3)        N.node->logPr = queried_value;
                                if(i==4)        N.node->Patch = queried_value;
                                if(i==5)        N.node->inversePatch = queried_value;

                        }

                }
        }
}

void GSMCreation(Graph &G, std::shared_ptr<seal::SEALContext> context, GaloisKeys &gal_keys, Evaluator &evaluator, seal::RelinKeys &relin_keys, const TFheGateBootstrappingCloudKeySet *EK)
{

        ifstream nodeNum("nodes/number_nodes");
        std::string t;
        std::getline(nodeNum,t);
        int nodenumber = atoi(t.c_str());
        nodeNum.close();

        ifstream edgeNum("edges/number_edges");
        std::getline(edgeNum,t);
        int edgenumber = atoi(t.c_str());
        edgeNum.close();

        G.node = new std::list<struct nodeList>;

        //node construction
        for(int i=0;i<nodenumber;i++)
        {
                struct nodeList P;
                P.visited = false;
                P.unchangeable = false;

                struct node *Pn = new struct node;
                Pn->user = false;
                Pn->T = new_gate_bootstrapping_ciphertext(EK->params);
                ifstream nodeTruth("nodes/nodeTruth"+to_string(i),std::ifstream::binary);
                import_gate_bootstrapping_ciphertext_fromStream(nodeTruth, Pn->T, EK->params);
                Pn->NodeNumber = i;
                Pn->Neighbors = new std::list<Neighbor>;
                P.node = Pn;
                G.node->push_back(P);
                nodeTruth.close();
        }
	//edge construction
        for(int i=0;i<edgenumber;i++)
        {
                ifstream edgeTruth("edges/edgeTruth"+to_string(i),std::ifstream::binary);
                ifstream edgeInfo("edges/edge"+to_string(i));
                std::string line;
                std::string token;
                std::getline(edgeInfo,line);
                stringstream ss(line);
                std::vector<int> edgeToFrom;
                while( ss >> token)
                {
                        edgeToFrom.push_back(atoi(token.c_str()));
                }
                nodeList n = findNode(G, edgeToFrom[0]);
                Neighbor P;
                P.NodeNumber = edgeToFrom[1];
                P.T = new_gate_bootstrapping_ciphertext(EK->params);
                import_gate_bootstrapping_ciphertext_fromStream(edgeTruth,P.T, EK->params);
                n.node->Neighbors->push_back(P);
                edgeTruth.close();
                edgeInfo.close();
        }
        //node information construction
        for(int i=0;i<nodenumber;i++)
        {
                processQuery(G,i,context,gal_keys,evaluator,relin_keys);
        }
}


