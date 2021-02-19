#include "struct.h"
#include "../function.h"
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
//a function that finds a specific node using nodeNumber
struct nodeList findNode(struct Graph &G, int nodeNumber){
        list<struct nodeList>::iterator iter;
        for(iter = G.node->begin(); (*iter).node->NodeNumber != nodeNumber; ++iter);
        return (*iter);
}

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
/////////////		functions used in evaluating a graph		////////////////

//find all possible path between source node and destination node with attack cost and risk
int num = 1;
/*
void probe(struct Graph& G, Ciphertext cost, Ciphertext risk, struct nodeList &N, LweSample* Tmp, vector<int> path, int dest, const TFheGateBootstrappingCloudKeySet* EK, const TFheGateBootstrappingSecretKeySet *PK, Evaluator &eval, auto &relin_keys, std::shared_ptr<seal::SEALContext> context, auto &secret_key){
	N.visited = true;
//	std::ofstream out("pathInfo.txt", std::ios::app);
//	std::ofstream outCost("SEAL.txt",std::ios::app);
//	std::ofstream outRisk("SEAL2.txt", std::ios::app);
//	std::ofstream outReal("TFHE.txt",std::ios::app);
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
		//cout << "path : ";
		//for(auto P : path)
		//{
		//	cout << P << " ";
		//}
		//cout << endl;
		Decryptor decryptor(context, secret_key);
                CKKSEncoder encoder(context);
                Plaintext cost_result, risk_result;
                decryptor.decrypt(cost, cost_result);
                decryptor.decrypt(risk,risk_result);
                vector<double> resultCost, resultRisk;
                encoder.decode(cost_result, resultCost);
                encoder.decode(risk_result, resultRisk);
                int real = bootsSymDecrypt(Tmp, PK);

		//cout <<"cost: " <<resultCost[0] << endl;
		//cout <<"risk: " <<resultRisk[0] <<endl;
		//cout <<"real: " <<real <<endl;
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
*/
//initial function to start probe
void init_probe(struct Graph& G, int startNumber, int destNumber, const TFheGateBootstrappingCloudKeySet* EK, const TFheGateBootstrappingSecretKeySet *PK, Evaluator &eval, seal::RelinKeys& relin_keys, seal::PublicKey public_key, std::shared_ptr<seal::SEALContext> context, seal::SecretKey secret_key){
	int graphSize = G.node->size();
	double scale = pow(2.0,40);
	CKKSEncoder encoder(context);
	Plaintext Risk;
	Plaintext Cost;
	encoder.encode(0, scale, Risk);
	encoder.encode(0, scale, Cost);
	Ciphertext Rst;
	Ciphertext cost;
	Encryptor encryptor(context, public_key);
	Ciphertext risk;
	encryptor.encrypt(Risk,risk);
	encryptor.encrypt(Cost,cost);

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
		// Temp - start
		vector<vector<int>> result_paths;
		vector<vector<int>> Paths;
		vector<int> S;
		S.push_back(startNumber);
		Paths.push_back(S);
		while(S.size()>0)
		{
			int c = S[S.size()-1];
			vector<int> p = Paths[Paths.size()-1];
			S.pop_back();
			Paths.pop_back();
			struct nodeList n__ = findNode(G,c);
			for(auto e : *(n__.node->Neighbors))
			{
				bool searched = false;
				for(auto x : p)
				{
					if(e.NodeNumber == x)	searched = true;
				}
				if(searched)	continue;
				if(e.NodeNumber == destNumber)
				{
					p.push_back(e.NodeNumber);
					result_paths.push_back(p);
				}
				else
				{
					// path update
					p.push_back(e.NodeNumber);

					// put into the stack.
					Paths.push_back(p);
					S.push_back(e.NodeNumber);
				}
			}
		}
		
		cout << "# of result paths : " << result_paths.size() << endl;

		// Calculate ciphertext part
		for (auto p : result_paths)
		{
			for(auto e : p)
			{
				struct nodeList N = findNode(G,e);
				if(N.node->user == false){
                			//calculate risk
                			eval.multiply(N.node->Impact,N.node->Pr,Rst);
                			eval.relinearize_inplace(Rst,relin_keys);
                			eval.rescale_to_next_inplace(Rst);
                			parms_id_type last_parms_id = Rst.parms_id();
                			Rst.scale() = pow(2.0,40);
                			eval.mod_switch_to_inplace(risk, last_parms_id);
                			eval.add_inplace(risk,Rst);

					//calculate cost
					eval.add_inplace(cost,N.node->Weight);
        			}
			}
		}

		// Temp - end
		/*diffRiskreturnOnInvestment(G, risk, inode, path, destNumber, diffRisk, EK, PK, eval, relin_keys, public_key, context, secret_key, Rst, encoder, encryptor);
		
		for(int i=0;i<graphSize;i++){
			if(i != target)	continue;
			struct nodeList targetNode;
			targetNode = findNode(G,i);
			parms_id_type last_parms_id = diffRisk[i].parms_id();
			diffRisk[i].scale() = pow(2.0,40);
			eval.mod_switch_to_inplace(targetNode.node->Patch, last_parms_id);
			eval.mod_switch_to_inplace(targetNode.node->inversePatch, last_parms_id);
			eval.sub_inplace(diffRisk[i], targetNode.node->Patch);
			eval.multiply_inplace(diffRisk[i], targetNode.node->inversePatch);

			std::ofstream out("return_on_investment_Info.txt", std::ios::app);
				if(out.is_open()){
					out <<"Node " <<i <<": ";
					diffRisk[i].save(out);
					out <<endl;
				}
		}
	*/	
		break;
	}	
	/*
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

		probe(G, cost, risk, inode, T, path, destNumber, EK, PK, eval,relin_keys, context, secret_key);
		delete_gate_bootstrapping_ciphertext(T);
		break;
	}
	*/
}

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
	//cout <<"pathNum: " <<routeNumber <<endl;
	//cout <<"totalHop: " <<totalHop <<endl;
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

void PrAtkSuccessProbe(struct Graph& G, Ciphertext &result, Ciphertext &base, Ciphertext logpr, struct nodeList& N, LweSample* Tmp, vector<int> path, vector<Ciphertext> &pathPr, int dest, const TFheGateBootstrappingCloudKeySet* EK, Evaluator &eval, seal::RelinKeys &relin_keys, std::shared_ptr<seal::SEALContext> context, seal::SecretKey secret_key){
//	cout << N.node->NodeNumber << endl;
//	std::ofstream out("probabilityInfo.txt", std::ios::app);
	if(N.node->user == false){
		eval.add_inplace(logpr,N.node->logPr);
        }
	path.push_back(N.node->NodeNumber);
	N.visited = true;
	list<struct Neighbor>::iterator iter;

	if(N.node->NodeNumber == dest){
		pathPr.push_back(logpr);
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
		//check probability value
		cout <<"path: ";
                for(auto P : path){
                        cout << P << " ";
                }
		cout <<endl;
*/
		CKKSEncoder encoder(context);	
		Decryptor decryptor(context, secret_key);
		Plaintext plain_result;
		decryptor.decrypt(logpr, plain_result);
		vector<double> result;
		encoder.decode(plain_result, result);
//		cout << "logPr: " <<result[0] <<endl;
		return;
	}
	else{
		for(iter = N.node->Neighbors->begin(); iter != N.node->Neighbors->end(); ++iter){
			list<struct nodeList>::iterator iter2;
				for(iter2 = G.node->begin(); iter2 != G.node->end(); ++iter2){
					if((*iter).NodeNumber == (*iter2).node->NodeNumber && (*iter2).visited == false){
						LweSample *Temp = new_gate_bootstrapping_ciphertext(EK->params);
						bootsAND(Temp,Tmp,(*iter).T,EK);
						PrAtkSuccessProbe(G, result, base, logpr, (*iter2), Tmp, path, pathPr, dest, EK, eval, relin_keys, context, secret_key);
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
	Plaintext logPr,Base,Result;
        encoder.encode(0, scale, logPr);
//	encoder.encode(1, scale, Base);
//	encoder.encode(1, scale, Result);

	Encryptor encryptor(context, public_key);
	Ciphertext logpr,base,result;
	encryptor.encrypt(logPr,logpr);
//	encryptor.encrypt(Base,base);
//	encryptor.encrypt(Result,result);

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
		vector<int> P;
		vector<Ciphertext> pathPr;
		
		//PrAtkSuccessProbe(G, result, base, logpr, inode, T, P, pathPr, destNumber, EK,eval,relin_keys, context, secret_key);
		
		vector<int> path;
                // Temp - start
                vector<vector<int>> result_paths;
                
		vector<vector<int>> Paths;
                vector<int> S;
                S.push_back(startNumber);
                Paths.push_back(S);
                while(S.size()>0)
                {
                        int c = S[S.size()-1];
                        vector<int> p = Paths[Paths.size()-1];
                        S.pop_back();
                        Paths.pop_back();
                        struct nodeList n__ = findNode(G,c);
                        for(auto e : *(n__.node->Neighbors))
                        {
                                bool searched = false;
                                for(auto x : p)
                                {
                                        if(e.NodeNumber == x)   searched = true;
                                }
                                if(searched)    continue;
                                if(e.NodeNumber == destNumber)
                                {
                                        p.push_back(e.NodeNumber);
                                        result_paths.push_back(p);
                                }
                                else
                                {
                                        // path update
                                        p.push_back(e.NodeNumber);

                                        // put into the stack.
                                        Paths.push_back(p);
                                        S.push_back(e.NodeNumber);
                                }
                        }
                }
		// Calculate ciphertext part
                for (auto p : result_paths)
                {
			Plaintext path_lg_pr;
		        encoder.encode(0, scale, path_lg_pr);
		        Ciphertext Path_lgpr;
		        encryptor.encrypt(path_lg_pr,Path_lgpr);

                        for(auto e : p)
                        {
                                struct nodeList N = findNode(G,e);
                                if(N.node->user == false){
					
                                        //calculate log_pr
					eval.add_inplace(Path_lgpr,N.node->logPr);
                                }
                        }
			pathPr.push_back(Path_lgpr);
                }

		Plaintext ResultPr;
		encoder.encode(0,scale,ResultPr);
		Ciphertext finalResult;
		encryptor.encrypt(ResultPr, finalResult);
		Decryptor decryptor(context, secret_key);

		int size = pathPr.size();
		cout <<size <<endl;

		for(int i=0;i<size;i++){

			//test
//			Plaintext plain_result1;
//        	        decryptor.decrypt(pathPr[i], plain_result1);
//                	vector<double> RST1;
//	                encoder.decode(plain_result1, RST1);
//	                cout <<"log(pr): " <<RST1[0] <<endl;

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

			//test
//			Plaintext plain_result2;
//	                decryptor.decrypt(temp0, plain_result2);
//        	        vector<double> result2;
//                	encoder.decode(plain_result2, result2);
//	                cout << "pr: " <<result2[0] <<endl;
	

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
                       
			//cout <<"temp7: " << context->get_context_data(secondtemp7.parms_id())->chain_index() <<endl;

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

			//test
//                        Plaintext plain_result3;
//                        decryptor.decrypt(secondtemp1, plain_result3);
//                        vector<double> result3;
//                        encoder.decode(plain_result3, result3);
//                        cout << "log(1-pr): " <<result3[0] <<endl;

//			last_parms_id = secondtemp1.parms_id();
//			eval.mod_switch_to_inplace(finalResult, last_parms_id);
//			eval.add_inplace(finalResult, secondtemp1);
		}
			//test
//                        Plaintext plain_result0;
//                        decryptor.decrypt(finalResult, plain_result0);
//                        vector<double> result0;
//                        encoder.decode(plain_result0, result0);
//                        cout << "result: " <<result0[0] <<endl;

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
/* deprecated... 
void diffRiskreturnOnInvestment(struct Graph &G, Ciphertext risk, struct nodeList &N, vector<int> path, int dest, vector<Ciphertext> &diffRisk, const TFheGateBootstrappingCloudKeySet* EK, const TFheGateBootstrappingSecretKeySet *PK, Evaluator &eval, seal::RelinKeys& relin_keys, seal::PublicKey &public_key, std::shared_ptr<seal::SEALContext> &context, seal::SecretKey &secret_key, Ciphertext &Rst, CKKSEncoder &encoder, Encryptor &encryptor){
	cout << N.node->NodeNumber << endl;
	int graphSize = G.node->size();
	double scale = pow(2.0,40);

	Ciphertext temp;
	Plaintext Temp;
	for(int i=0;i<graphSize;i++){
		encoder.encode(0, scale, Temp);
		encryptor.encrypt(Temp,temp);
		diffRisk.push_back(temp);
	}
	
	N.visited = true;
	if(N.node->user == false){
		//calculate risk
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
		cout <<"path: ";
		for(auto Path : path){
			cout <<Path <<" ";
			parms_id_type last_parms_id = risk.parms_id();
			risk.scale() = pow(2.0,40);
			eval.mod_switch_to_inplace(diffRisk[Path], last_parms_id);
			eval.add_inplace(diffRisk[Path], risk);
		}
		cout << endl;
	}
	else{
		for(iter = N.node->Neighbors->begin(); iter != N.node->Neighbors->end(); ++iter){
			list<struct nodeList>::iterator iter2;
			for(iter2 = G.node->begin(); iter2 != G.node->end(); ++iter2){
				if((*iter).NodeNumber == (*iter2).node->NodeNumber && (*iter2).visited == false){
					diffRiskreturnOnInvestment(G, risk, (*iter2), path, dest, diffRisk, EK, PK, eval, relin_keys, public_key, context, secret_key, Rst, encoder, encryptor);
					(*iter2).visited = false;
				}
			}
		}
	}
	N.visited = false;
	return;
}
*/
//function to calculate return on investment
void returnInvestment(struct Graph& G, int startNumber, int destNumber, int target, const TFheGateBootstrappingCloudKeySet* EK, const TFheGateBootstrappingSecretKeySet *PK, Evaluator &eval, seal::RelinKeys& relin_keys, seal::PublicKey public_key, std::shared_ptr<seal::SEALContext> context, seal::SecretKey secret_key){
	int graphSize = G.node->size();
	double scale = pow(2.0,40);
	CKKSEncoder encoder(context);
	Plaintext Risk;
	encoder.encode(0, scale, Risk);

	Ciphertext Rst;

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
		// Temp - start
		vector<vector<int>> Patched_paths;
		vector<vector<int>> Paths;
		vector<int> S;
		S.push_back(startNumber);
		Paths.push_back(S);
		while(S.size()>0)
		{
			int c = S[S.size()-1];
			vector<int> p = Paths[Paths.size()-1];
			S.pop_back();
			Paths.pop_back();
			struct nodeList n__ = findNode(G,c);
			for(auto e : *(n__.node->Neighbors))
			{
				bool searched = false;
				for(auto x : p)
				{
					if(e.NodeNumber == x)	searched = true;
				}
				if(searched)	continue;
				if(e.NodeNumber == destNumber)
				{
					p.push_back(e.NodeNumber);
					bool patched = false;
					for(auto x : p)
						if(x == target)	patched = true;
					if(!patched)	continue;
					Patched_paths.push_back(p);
				}
				else
				{
					// path update
					p.push_back(e.NodeNumber);

					// put into the stack.
					Paths.push_back(p);
					S.push_back(e.NodeNumber);
				}
			}
		}
		//cout << " # of Patched path : " << Patched_paths.size() << endl;
		// Calculate ciphertext part
		for (auto p : Patched_paths)
		{
			for(auto e : p)
			{
				//cout << e << " ";
				struct nodeList N = findNode(G,e);
				if(N.node->user == false){
                			//calculate risk
                			eval.multiply(N.node->Impact,N.node->Pr,Rst);
                			eval.relinearize_inplace(Rst,relin_keys);
                			eval.rescale_to_next_inplace(Rst);
                			parms_id_type last_parms_id = Rst.parms_id();
                			Rst.scale() = pow(2.0,40);
                			eval.mod_switch_to_inplace(risk, last_parms_id);
                			eval.add_inplace(risk,Rst);
        			}
			}
			//cout << endl;
		}
		struct nodeList targetNode = findNode(G,target);
		parms_id_type last_parms_id = risk.parms_id();
		risk.scale() = pow(2.0,40);
		eval.mod_switch_to_inplace(targetNode.node->Patch, last_parms_id);
		eval.mod_switch_to_inplace(targetNode.node->inversePatch, last_parms_id);
		eval.sub_inplace(risk, targetNode.node->Patch);
		eval.multiply_inplace(risk, targetNode.node->inversePatch);		

		// Temp - end
		/*diffRiskreturnOnInvestment(G, risk, inode, path, destNumber, diffRisk, EK, PK, eval, relin_keys, public_key, context, secret_key, Rst, encoder, encryptor);
		
		for(int i=0;i<graphSize;i++){
			if(i != target)	continue;
			struct nodeList targetNode;
			targetNode = findNode(G,i);
			parms_id_type last_parms_id = diffRisk[i].parms_id();
			diffRisk[i].scale() = pow(2.0,40);
			eval.mod_switch_to_inplace(targetNode.node->Patch, last_parms_id);
			eval.mod_switch_to_inplace(targetNode.node->inversePatch, last_parms_id);
			eval.sub_inplace(diffRisk[i], targetNode.node->Patch);
			eval.multiply_inplace(diffRisk[i], targetNode.node->inversePatch);

			std::ofstream out("return_on_investment_Info.txt", std::ios::app);
				if(out.is_open()){
					out <<"Node " <<i <<": ";
					diffRisk[i].save(out);
					out <<endl;
				}
		}
	*/	
		break;
	}
}









//function to normalize degrees of all nodes
std::vector<double> getNormalizedDegree(struct Graph& G)
{
	struct degree D = getDegree(G);
	std::vector<int> Table = totalDegree(D);

	int maxValue = 0;
	
	int L = Table.size();
	for(int i = 0; i < L; i++)
	{
		if(Table[i] > maxValue)
		{
			maxValue = Table[i];
		}
	}

	if(maxValue == 0)
	{
		cout << "There is something wrong on getting max value. Exit" << endl;
		exit(0);
	}

	std::vector<double> retVec;
	for(int i = 0; i < L; i++)
	{
		retVec.push_back((double)Table[i]/(double)maxValue);
	}
	return retVec;
}

//function to calculate closeness centralities of all nodes
vector<double> closeness(Graph& G, const TFheGateBootstrappingCloudKeySet* EK)
{
	vector<double> ret;
	int n = G.node->size();	
	
	for(int i = 0; i < n; i++)
	{
		int S = 0;
		for(int j = 0; j < n; j++)
		{
			if(i != j)
			{
				int Ccost = minCut(G, i, j, EK);
				if(Ccost < 1000000)
				{
					S+=Ccost-1;
				}
			}
		}
		ret.push_back((double)(n-1)/(double)S);
	}
	return ret;
}


//a function to normalize closeness centralities
vector<double> normalizedCloseness(Graph& G, const TFheGateBootstrappingCloudKeySet* EK)
{
	vector<double> C = closeness(G,EK);
	int L = C.size();
	double maxValue = 0;	

	for(int i = 0; i < L; i++)
	{
		if(maxValue < C[i])
		{
			maxValue = C[i];
		}
	}

	if(maxValue == 0)
	{
		cout << "There is something wrong on getting max value. Exit" << endl;
                exit(0);
	}
	for(int i = 0; i < L; i ++)
	{
		C[i] /= maxValue;
	}
	return C;
}


//a function to calculate harmonic centralities of all nodes
vector<double> harmonic(Graph& G, const TFheGateBootstrappingCloudKeySet* EK)
{
	vector<double> ret;
	int n = G.node->size();	
	
	for(int i = 0; i < n; i++)
	{
		double S = 0;
		for(int j = 0; j < n; j++)
		{
			if(i != j)
			{
				int Ccost = minCut(G, i, j, EK)-1;
				if(Ccost < 999999)
				{
					S += (double)1.0f/((double)Ccost);
				}
			}
		}
		ret.push_back(S);
	}
	return ret;
}


//a function to normalize harmonic centralities
vector<double> normalizedHarmonic(Graph& G, const TFheGateBootstrappingCloudKeySet* EK)
{
        vector<double> H = harmonic(G,EK);
        int L = H.size();
        double maxValue = 0;

        for(int i = 0; i < L; i++)
        {
                if(maxValue < H[i])
                {
                        maxValue = H[i];
                }
        }

        if(maxValue == 0)
        {
                cout << "There is something wrong on getting max value. Exit" << endl;
                exit(0);
        }
        for(int i = 0; i < L; i ++)
        {
                H[i] /= maxValue;
        }
        return H;
}


//a function to extract nodes from a path except endpoints
void extract(struct Graph& G, vector<vector<int>>* T, struct nodeList& N, int length, vector<int> path, int dest, const TFheGateBootstrappingCloudKeySet* EK){
       	path.push_back(N.node->NodeNumber);
	if(path.size() > length){
		return;
	}
	else{
	        N.visited = true;
	        list<struct Neighbor>::iterator iter;
	        for(iter = N.node->Neighbors->begin(); iter != N.node->Neighbors->end(); ++iter)
	        {
	                list<struct nodeList>::iterator iter2; 
	                for(iter2 = G.node->begin(); iter2 != G.node->end(); ++iter2)
	                {
	                        if((*iter).NodeNumber == (*iter2).node->NodeNumber && (*iter2).visited == false)
	                        {
	                                extract(G, T, (*iter2), length, path, dest, EK);
	                        }
	                }
	        }
	        if(N.node->NodeNumber == dest && path.size() == length)
	        {
			T->push_back(path);
	        }
       	 	N.visited = false;
	}
}


//a function to calculate betweenness centralities of all nodes
vector<double> betweenness(Graph& G, const TFheGateBootstrappingCloudKeySet* EK)
{

	int graphSize = G.node->size();
	double Table[graphSize];

	for(int i = 0; i < graphSize; i++)
	{
		Table[i] = 0;
	}

	for(int i = 0; i < graphSize; i++)
	{
		for(int j = 0; j < graphSize; j++)
		{
			if(i != j && i == 0 && j == graphSize-1)
			{
				int RouteNumber = 0;
				int minLength = minCut(G, i, j, EK);

				std::list<struct nodeList>::iterator iter;
				for(iter = G.node->begin(); (*iter).node->NodeNumber != i; ++iter);

				vector<vector<int>> T;
				vector<int> t;
				extract(G, &T, (*iter), minLength, t, j, EK);

				int Tsize = T.size();
				for(int k = 0; k < Tsize; k++)
				{
					int Lsize = T[k].size();
					for(int l = 1; l < Lsize-1; l++)
					{
						Table[T[k][l]] += (double)1.0f/(double)Tsize;
					}
				}
			}
		}
	}
	vector<double> ret;
	for(int i = 0; i < graphSize; i++)
	{
		ret.push_back(Table[i]);
	}
	return ret;
}


//a funtion to normalize betweenness centralities
vector<double> normalizedBetweenness(Graph& G, const TFheGateBootstrappingCloudKeySet* EK)
{
        vector<double> B = betweenness(G,EK);
        int L = B.size();
        double maxValue = 0;

        for(int i = 0; i < L; i++)
        {
                if(maxValue < B[i])
                {
                        maxValue = B[i];
                }
        }

        if(maxValue == 0)
        {
                cout << "There is something wrong on getting max value. Exit" << endl;
                exit(0);
        }
        for(int i = 0; i < L; i ++)
        {
                B[i] /= maxValue;
        }
        return B;
}


//a function used in calculating 
void extract2(struct Graph& G, vector<vector<int>>* T, struct nodeList& N, vector<int> path, int dest, const TFheGateBootstrappingCloudKeySet* EK){
	path.push_back(N.node->NodeNumber);

        N.visited = true;

        list<struct Neighbor>::iterator iter;

        for(iter = N.node->Neighbors->begin(); iter != N.node->Neighbors->end(); ++iter)
        {
                list<struct nodeList>::iterator iter2;
                for(iter2 = G.node->begin(); iter2 != G.node->end(); ++iter2)
                {
                        if((*iter).NodeNumber == (*iter2).node->NodeNumber && (*iter2).visited == false)
                        {
                                extract2(G, T, (*iter2), path, dest, EK);
                        }
                }
        }

	if(N.node->NodeNumber == dest)
        {
                T->push_back(path);
        }

        N.visited = false;
}

//baseline for comparing efficency of heuristic algorithm.
	//just add edges randomly in graph
void addRandomlyOnlyEdges(struct Graph& G, int dummyEdgesNum, const TFheGateBootstrappingCloudKeySet* EK){
	int graphSize = G.node->size();
	
	for(int i=0; i<dummyEdgesNum; i++){		
		int from = rand() % graphSize;
		int to = rand() % graphSize;
		//start node and end node cannot be same.
		if(to == from){
			while(to == from){
				to = rand() % graphSize;
			}
		}

		//check edge is already exist.
		bool exist = false;
		struct nodeList startNode = findNode(G, from);
		list <struct Neighbor>::iterator iter;
		for(iter = startNode.node->Neighbors->begin(); iter != startNode.node->Neighbors->end(); iter++){
			if((*iter).NodeNumber == to){
				exist = true;
				break;
			}
		}

		if(exist == false){
			createDummyEdge(G, from, to, false, EK);
			createDummyEdge(G, to, from, false, EK);
			//test about adding random edge
        	        //cout <<"from " <<from <<" to " <<to <<endl;

		}
		else{
			i--;
			exist = false;
		}
	}
//	cout <<"adding edges complete!" <<endl <<endl;
}


	//just add edges, nodes randomly in graph
void addRandomlyEdgesNodes(struct Graph& G, int dummyNodesNum, int graphSize, const TFheGateBootstrappingCloudKeySet* EK, const TFheGateBootstrappingSecretKeySet *PK, seal::PublicKey public_key, std::shared_ptr<seal::SEALContext> context){
	for(int i=0; i<dummyNodesNum; i++){
		double avgDeg=0;
		double gS = G.node->size();
		struct degree nodeDegree = getDegree(G);
		vector<struct degInfo> Vin = nodeDegree.Vin;
		for(int i=0;i<gS;i++){
			avgDeg += Vin[i].Degree;
		}
		avgDeg = avgDeg / (double)gS;

//		cout <<"Average Degree: " <<avgDeg <<endl;

		createDummyNode(G, 10, 10, 0.0, -1000.0, 1, 1, PK, public_key,context);
		int s = G.node->size();
		for(int a=0;a<avgDeg;a++){
//		for(int a=0;a<1;a++){
			int from = rand() % graphSize;
			bool exist = false;
	                struct nodeList startNode = findNode(G, from);
        	        list <struct Neighbor>::iterator iter;
                	for(iter = startNode.node->Neighbors->begin(); iter != startNode.node->Neighbors->end(); iter++){
                	        if((*iter).NodeNumber == s){
                        	        exist = true;
                                	break;
	                        }
	                }
			if(exist==false){
				createDummyEdge(G, from, G.node->size()-1, false, EK);
				createDummyEdge(G, G.node->size()-1, from, false, EK);
//				cout <<"random added edge: " <<from <<"-----------" <<G.node->size()-1 <<endl;
			}
			else{
				a--;
				exist = false;
			}
		}
	}

//	cout <<"adding nodes, edges complete!" <<endl <<endl;
}

vector<double> BetweennessCentrality(Graph& G, const TFheGateBootstrappingCloudKeySet* EK,int source, int dest){
	int graphSize = G.node->size();
        double Table[graphSize];
	int pathNum = 0;

        for(int i = 0; i < graphSize; i++)
        {
                Table[i] = 0;
        }

        for(int i = 0; i < graphSize; i++)
        {
                for(int j = 0; j < graphSize; j++)
                {
                        if(i != j && i == source && j==dest)
                        {
                                int RouteNumber = 0;
				//cout <<"test1 - source: " <<i <<", destination: " <<j <<endl;
				int minLength = minCut(G, i, j, EK);
				if(minLength != 1000000){
					//cout <<"test2" <<endl;
	                                std::list<struct nodeList>::iterator iter;
	                                for(iter = G.node->begin(); (*iter).node->NodeNumber != i; ++iter);
	
	                                vector<vector<int>> T;
	                                vector<int> t;
	                                extract(G, &T, (*iter), minLength, t, j, EK);
	
	                                int Tsize = T.size();
	        			pathNum += Tsize;
					for(int k = 0; k < Tsize; k++)
	                                {
	                                        int Lsize = T[k].size();
	                                        for(int l = 0; l < Lsize-1; l++)
	                                        {
	                                                Table[T[k][l]] += (double)1.0f/(double)Tsize;
	                                        }
					}
				}
			}
                }
        }
        vector<double> ret;
	if(pathNum == 0){
	//	cout <<"There is no path." <<endl;
		for(int i=0;i<graphSize;i++){
                        ret.push_back(0);
                }
	}
	else{
	        for(int i = 0; i < graphSize; i++)
	        {
	                ret.push_back(Table[i]);
	        }
	}
        return ret;
}


vector<double> allPathBetweennessCentrality(Graph& G, const TFheGateBootstrappingCloudKeySet* EK, int source, int dest){
        int gs = G.node->size();
        double Table[gs];
        int totalPathNum = 0;

        //start to calculate centralities
        for(int i = 0; i < gs; i++)
        {
                Table[i] = 0;
        }

        for(int i = 0; i < gs; i++)
        {
                for(int j = 0; j < gs; j++)
                {
                        //if(i != j)
                        if(i != j && i == source && j==dest)   //destination node is fixed (j is fixed)
                        {
                                std::list<struct nodeList>::iterator iter;
                                for(iter = G.node->begin(); (*iter).node->NodeNumber != i; ++iter);

                                vector<vector<int>> T;
                                vector<int> t;
               
//				cout <<"start' - " <<(*iter).node->NodeNumber <<", " <<dest <<endl;
       
				extract2(G, &T, (*iter), t, j, EK);

                                int Tsize = T.size();
                                totalPathNum += Tsize;
                                for(int k = 0; k < Tsize; k++)
                                {
                                        int Lsize = T[k].size();
                                        for(int l = 0; l < Lsize; l++)
                                        {
                                                Table[T[k][l]] += (double)1.0f;
                                        }
                                }
                        }
                }
        }

        vector<double> ret;
//      cout <<"total path num: " <<totalPathNum <<endl;        //check a number of paths

        if(totalPathNum == 0){
//		cout <<"There isn't any path go to the destination node, so path betweenness centrality of all nodes are setted as value 0." <<endl;
                for(int i=0;i<gs;i++){
                        ret.push_back(0);
                }
        }
        else{
                for(int i = 0; i < gs; i++)
                {
                        ret.push_back(Table[i]/(double)totalPathNum);
                }
        }
        return ret;
}


vector<double> weightedPathBetweennessCentrality(Graph& G, const TFheGateBootstrappingCloudKeySet* EK,int source, int dest){
        int gs = G.node->size();
        double Table[gs];
        int totalPathNum = 0;

        //start to calculate centralities
        for(int i = 0; i < gs; i++)
        {
                Table[i] = 0;
        }

        for(int i = 0; i < gs; i++)
        {
                for(int j = 0; j < gs; j++)
                {
                        //if(i != j)
                        if(i != j && i == source && j==dest)   //destination node is fixed (j is fixed)
                        {
                                std::list<struct nodeList>::iterator iter;
                                for(iter = G.node->begin(); (*iter).node->NodeNumber != i; ++iter);

                                vector<vector<int>> T;
                                vector<int> t;
                                extract2(G, &T, (*iter), t, j, EK);

                                int Tsize = T.size();
                                totalPathNum += Tsize;
                                for(int k = 0; k < Tsize; k++)
                                {
                                        int Lsize = T[k].size();
                                        for(int l = 0; l < Lsize; l++)
                                        {
                                                Table[T[k][l]] += (double)1.0f/Lsize;
                                        }
                                }
                        }
                }
        }

        vector<double> ret;
	//      cout <<"total path num: " <<totalPathNum <<endl;        //check a number of paths

        if(totalPathNum == 0){
//                cout <<"There isn't any path go to the destination node, so path betweenness centrality of all nodes are setted as value 0." <<endl;
                for(int i=0;i<gs;i++){
                        ret.push_back(0);
                }
        }
        else{
                for(int i = 0; i < gs; i++)
                {
                        ret.push_back(Table[i]);
                }
        }
        return ret;
}


//increasing order
bool cmp2(const pair<int, int> &a, const pair<int, int> &b)
{
    return a.second < b.second;
}


vector<double> someBetweennessCen(Graph &G, const TFheGateBootstrappingCloudKeySet* EK, int dest, set<int> &sourceNodeSet){
	int graphSize = G.node->size();
	double Table[graphSize];
        for(int i = 0; i < graphSize; i++)
        {
                Table[i] = 0;
        }

        for(int i = 0; i < graphSize; i++)
        {
                std::set<int>::iterator it = sourceNodeSet.find(i);
                if( it != sourceNodeSet.end()){         //when i is included in sourceNodeSet.
//                      cout <<"start - " <<i <<", " <<dest <<endl;

                        vector<double> tempCen = BetweennessCentrality(G, EK, i, dest);
                        for(int k=0;k<graphSize;k++){
                                Table[k] += tempCen[k];
                        }
                }
                else{
                       continue;
                }
        }

        vector<double> ret;
        for(int i = 0; i < graphSize; i++)
        {
                ret.push_back(Table[i]/(double)sourceNodeSet.size());
        }

/*
        for(int i=0; i<graphSize;i++){
                cout << ret[i] <<", ";
        }
        cout <<endl;
*/

        return ret;	
}


vector<double> somePathBetCen(Graph& G, const TFheGateBootstrappingCloudKeySet* EK, int dest, set<int> &sourceNodeSet){
	int graphSize = G.node->size();
        int totalPathNum = 0;
/*
        //check source node set
        for(set<int>::iterator it = sourceNodeSet.begin(); it != sourceNodeSet.end(); ++it){
                cout << *it <<" ";
        }
        cout <<endl;
*/

	//start to calculate centralities
        double Table[graphSize];
	for(int i = 0; i < graphSize; i++)
        {
                Table[i] = 0;
        }

        for(int i = 0; i < graphSize; i++)
        {
                std::set<int>::iterator it = sourceNodeSet.find(i);
                if( it != sourceNodeSet.end()){         //when i is included in sourceNodeSet.
//			cout <<"start - " <<i <<", " <<dest <<endl;

			vector<double> tempCen = allPathBetweennessCentrality(G, EK, i, dest);
			for(int k=0;k<graphSize;k++){
				Table[k] += tempCen[k];
			}
		}
		else{
                       continue;
                }
        }

        vector<double> ret;
//      cout <<"total path num: " <<totalPathNum <<endl;        //check a number of paths       
        for(int i = 0; i < graphSize; i++)
        {
                ret.push_back(Table[i]/(double)sourceNodeSet.size());
        }

/*
	for(int i=0; i<graphSize;i++){
		cout << ret[i] <<", ";
	}
	cout <<endl;
*/

        return ret;
}


//a function to make decrease a path centrality betweenness of destination node.
//decresaing order
bool cmp(const pair<int, double> &a, const pair<int, double> &b)
{
    return a.second > b.second;
}
//increasing order
bool cmp1(const pair<int, double> &a, const pair<int, double> &b)
{
    return a.second < b.second;
}

void heuristicOnlyEdges2(struct Graph &G, int sourceNode, int destinationNode, const TFheGateBootstrappingCloudKeySet* EK){
        vector<double> pathCen = allPathBetweennessCentrality(G, EK, sourceNode, destinationNode);
//      cout <<pathCen <<endl;
	int gSize = G.node->size();
	vector<pair<int,double>> sortedPathBetCen;
        for(int i=0; i<gSize; i++){
                sortedPathBetCen.push_back(make_pair(i,pathCen[i]));
        }
        sort(sortedPathBetCen.begin(), sortedPathBetCen.end(),cmp1);	//increasing order
	for(int i=0;i<gSize;i++){
		cout <<sortedPathBetCen[i].first <<", " <<sortedPathBetCen[i].second <<endl;
	}
	int index = 0;
        int from, to;
	double min_cen = sortedPathBetCen[index].second;
	int min_num = 0;
	while(sortedPathBetCen[index].second == min_cen){
		min_num++;
		index++;
	}
	if(min_num >= 2){
		index = rand() % min_num;
	        from = sortedPathBetCen[index].first;
	        while(from == sourceNode || from == destinationNode){
	                index = rand() % min_num;
	                from = sortedPathBetCen[index].first;
	        }
		index = rand() % min_num;
		to = sortedPathBetCen[index].first;
		while(to == sourceNode || to == destinationNode || to == from){
	                index = rand() % min_num;
	                to = sortedPathBetCen[index].first;
	        }
	}
	else{
		from = sortedPathBetCen[0].first;
		min_num = 0;
		min_cen = sortedPathBetCen[index].second;
		while(sortedPathBetCen[index].second == min_cen){
	                min_num++;
        	        index++;
        	}
		index = rand() % min_num;
		index ++;
		to = sortedPathBetCen[index].first;
		while(to == sourceNode || to == destinationNode || to == from){
                        index = rand() % min_num;
			index++;
                        to = sortedPathBetCen[index].first;
                }
	}
	cout << to <<", " <<from <<endl;
	createDummyEdge(G,to,from,false,EK);
	createDummyEdge(G,from,to,false,EK);
/*
        vector<pair<int,int>> distanceFromDest;
        for(int i=0;i<gSize;i++){
                int dist = minCut(G,i,destinationNode,EK)-1;
                distanceFromDest.push_back(make_pair(i,dist));
        }

        sort(distanceFromDest.begin(), distanceFromDest.end(), cmp1);

        //check sorted result
        for(int i=0;i<gSize;i++){
                cout <<distanceFromDest[i].first <<", " <<distanceFromDest[i].second <<endl;
	}
*/
        return;
}

void heuristicAddNodes(struct Graph &G, int destinationNode, int dummyNode, vector<double> betweennessCen, const TFheGateBootstrappingCloudKeySet* EK, const TFheGateBootstrappingSecretKeySet *PK, seal::PublicKey public_key, std::shared_ptr<seal::SEALContext> context){
	int graphSize = G.node->size();
	vector<pair<int, double>> temp;
	for(int i=0;i<graphSize;i++){
		temp.push_back(make_pair(i,betweennessCen[i]));
	}
	sort(temp.begin(), temp.end(), cmp);
/*
	//check sorted path centrality
	for(int i=0;i<graphSize;i++){
		cout <<temp[i].first <<", " <<temp[i].second <<endl;
	}
*/
	vector<int> startNodeSet;
	int index = 0;
	double temp_Cen = temp[index].second;
	while(temp_Cen == temp[index].second){
		int source = temp[index].first;
		if(source != destinationNode){
			startNodeSet.push_back(source);
		}
		index++;
	}
	if(startNodeSet.empty()){
		temp_Cen = temp[index].second;
		while(temp_Cen == temp[index].second){
                	int source = temp[index].first;
                	if(source != destinationNode){
				startNodeSet.push_back(source);
                	}
                	index++;
		}
	}
//	cout <<index <<", " <<startNodeSet.size() <<endl;

	for(int i=0;i<dummyNode;i++){
		double avgDeg=0;
		double gS = G.node->size();
                struct degree nodeDegree = getDegree(G);
                vector<struct degInfo> Vin = nodeDegree.Vin;
                for(int i=0;i<gS;i++){
                        avgDeg += Vin[i].Degree;
                }
                avgDeg = avgDeg / (double)gS;

//                cout <<"Average Degree: " <<avgDeg <<endl;

		int sz = startNodeSet.size();
		int ran = rand() % sz;
		int startNodeNumber = startNodeSet[ran];
	
	//	cout <<"start node: " <<startNodeNumber <<endl;
	
		createDummyNode(G, 10, 10, 0.0, -1000.0, 1, 1, PK, public_key, context);

		for(int a=0;a<avgDeg;a++){	
	//	cout <<G.node->size()-1 <<endl;
			createDummyEdge(G, temp[a].first, G.node->size()-1, true, EK);
			createDummyEdge(G, G.node->size()-1, temp[a].first, true, EK);
//		cout <<"added edge: " <<temp[a].first  <<"--" <<G.node->size()-1 <<endl;
		}
	}
}

void probePath(struct Graph& G, struct nodeList& N,  int* routeNumber, int dest){
	N.visited = true;
	list<struct Neighbor>::iterator iter;
	if(N.node->NodeNumber == dest){
		*routeNumber = (*routeNumber) + 1;
	}
	else{
		for(iter = N.node->Neighbors->begin(); iter != N.node->Neighbors->end(); ++iter){
			list<struct nodeList>::iterator iter2;
			for(iter2 = G.node->begin(); iter2 != G.node->end(); ++iter2){
				if((*iter).NodeNumber == (*iter2).node->NodeNumber && (*iter2).visited == false){
                                        probePath(G, (*iter2), routeNumber, dest);
                                }
                        }
                }
        }
        N.visited = false;
}

//find a number of path
void countTotalPath(struct Graph& G, int startNumber, int destNumber){
        int routeNumber = 0;
        list<struct nodeList>::iterator iter;
        for(iter = G.node->begin(); iter != G.node->end(); ++iter){
		(*iter).visited = false;
	}
	for(iter = G.node->begin(); (*iter).node->NodeNumber != startNumber; ++iter);
        probePath(G, *iter, &routeNumber, destNumber);
	if(routeNumber != 0){
		cout <<routeNumber <<"\t";
	}
}

void eraseEdge(struct Graph &G, int start, int end){
//	cout <<"want to erase: " <<start <<"--->" <<end <<endl;
	for(list<nodeList>::iterator N = G.node->begin(); N != G.node->end(); ++N){
		if((*N).node->NodeNumber == start){
//			cout <<"find" <<start <<endl;
			for(list<Neighbor>::iterator Nn = (*N).node->Neighbors->begin();Nn != (*N).node->Neighbors->end(); ++Nn){
				if(Nn->NodeNumber==end){
//					cout <<"delete: " <<(*N).node->NodeNumber <<"--->" <<Nn->NodeNumber <<endl;
					(*N).node->Neighbors->erase(Nn++);
					if(Nn == (*N).node->Neighbors->end())   break;
				}
			if(Nn == (*N).node->Neighbors->end())   break;
			}
		}
	}
}

//change a bidirected graph into directed graph
void changeGraph(struct Graph &G, int source){
	int cnt =0;
	queue<int> searchingNode;
	searchingNode.push(source);

	while(!searchingNode.empty()){
		int current = searchingNode.front();
//		cout <<"current: " <<current <<endl;
		searchingNode.pop();
		struct nodeList currentNode = findNode(G, current);
		list<struct Neighbor>::iterator iter;
		for(iter = currentNode.node->Neighbors->begin(); iter != currentNode.node->Neighbors->end();++iter){
			int next = (*iter).NodeNumber;
			searchingNode.push(next);
			eraseEdge(G, next, current);
		}
	}
	return;
}

void heuristicAddNodes2(struct Graph &G, int destinationNode, int dummyNode, vector<double> betweennessCen, const TFheGateBootstrappingCloudKeySet* EK, const TFheGateBootstrappingSecretKeySet *PK, seal::PublicKey public_key, std::shared_ptr<seal::SEALContext> context){
        int graphSize = G.node->size();

//	cout <<"heuristic2 start" <<endl;

//	vector<double> someBetCen = someBetweennessCen(G, EK, destinationNode, sourceNodeSet);

//	cout <<"calculating betCen finished" <<endl;

	vector<pair<int, double>> temp;
        for(int i=0;i<graphSize;i++){
                temp.push_back(make_pair(i,betweennessCen[i]));
        }
        sort(temp.begin(), temp.end(), cmp);
//	vector<int> startNodeSet;
//	int index = 0;
//	double temp_Cen = temp[index].second;
//	while(temp_Cen == temp[index].second){
//		int source = temp[index].first;
//		if(source != destinationNode){
//			startNodeSet.push_back(source);
//		}
//		index++;
//	}
//	if(startNodeSet.empty()){
//		temp_Cen = temp[index].second;
//		while(temp_Cen == temp[index].second){
//		int source = temp[index].first;
//			if(source != destinationNode){
//				startNodeSet.push_back(source);
//			}
//			index++;
//		}
//	}
//	int sz = startNodeSet.size();
//	int ran = rand() % sz;
//	int startNodeNumber = startNodeSet[ran];
        for(int i=0;i<dummyNode;i++){
		createDummyNode(G, 10, 10, 0.0, -1000.0, 1, 1, PK, public_key, context);
		createDummyEdge(G, temp[i].first, G.node->size()-1, true, EK);
		createDummyEdge(G, G.node->size()-1, temp[i].first, true, EK);
//		cout <<"added edge: " <<temp[i].first <<"-----" <<G.node->size()-1 <<endl;
	}
}

void heuristicAddNodesDB(struct Graph &G, int destinationNode, int dummyNode, vector<struct degInfo> Vin, const TFheGateBootstrappingCloudKeySet* EK, const TFheGateBootstrappingSecretKeySet *PK, seal::PublicKey public_key, std::shared_ptr<seal::SEALContext> context){
        int graphSize = G.node->size();
        vector<pair<int, int>> temp;
        for(int i=0;i<graphSize;i++){
                temp.push_back(make_pair(i,Vin[i].Degree));
        }
        sort(temp.begin(), temp.end(), cmp);
/*
        //check sorted path centrality
        for(int i=0;i<graphSize;i++){
                cout <<temp[i].first <<", " <<temp[i].second <<endl;
        }
*/
        vector<int> startNodeSet;
        int index = 0;
        double temp_Deg = temp[index].second;
        while(temp_Deg == temp[index].second){
                int source = temp[index].first;
                if(source != destinationNode){
                        startNodeSet.push_back(source);
                }
                index++;
        }
        if(startNodeSet.empty()){
                temp_Deg = temp[index].second;
                while(temp_Deg == temp[index].second){
                        int source = temp[index].first;
                        if(source != destinationNode){
                                startNodeSet.push_back(source);
                        }
                        index++;
                }
        }
//      cout <<index <<", " <<startNodeSet.size() <<endl;
        for(int i=0;i<dummyNode;i++){
                double avgDeg=0;
                double gS = G.node->size();
                struct degree nodeDegree = getDegree(G);
                vector<struct degInfo> V = nodeDegree.Vin;
                for(int i=0;i<gS;i++){
                        avgDeg += V[i].Degree;
                }
                avgDeg = avgDeg / (double)gS;

//                cout <<"Average Degree: " <<avgDeg <<endl;

                int sz = startNodeSet.size();
                int ran = rand() % sz;
                int startNodeNumber = startNodeSet[ran];

        //      cout <<"start node: " <<startNodeNumber <<endl;

                createDummyNode(G, 10, 10, 0.0, -1000.0, 1, 1, PK, public_key, context);

                for(int a=0;a<avgDeg;a++){
        //      cout <<G.node->size()-1 <<endl;
                        createDummyEdge(G, temp[a].first, G.node->size()-1, true, EK);
                        createDummyEdge(G, G.node->size()-1, temp[a].first, true, EK);
//                cout <<"added edge: " <<temp[a].first  <<"--" <<G.node->size()-1 <<endl;
                }
        }
}
int shortestPathattack(Graph &G, int start, int end, const TFheGateBootstrappingCloudKeySet *EK, const TFheGateBootstrappingSecretKeySet *PK)
{
	std::vector<std::vector<int>> temp;
	std::vector<std::vector<int>> pathlist;
	int mincut = minCut(G, start, end, EK);

	if(mincut == 1000000) return 0;

	std::vector<int> stack;
	for(auto inode : *(G.node))	inode.visited = false;
	for(auto inode : *(G.node)){
		if(inode.node->NodeNumber == start){
			inode.visited = true;
			stack.push_back(start);
			break;
		}
	}
	std::vector<int> T;
	T.push_back(start);
	temp.push_back(T);

	//cout << "mincut : " << mincut << endl;

	// Path finding algorithm...
	while(stack.size()>0)
	{
		// stack pop.
		int cur = stack[stack.size()-1];
		stack.pop_back();
		T = temp[temp.size()-1];
		temp.pop_back();
		
		if(cur == end)
		{
			pathlist.push_back(T);
			continue;
		}
		if(T.size()>=mincut)	continue;
		nodeList n = findNode(G,cur);

		for(auto N : *(n.node->Neighbors))
		{
			bool dup = false;
			for(auto e : T)
			{
				if(e == N.NodeNumber) dup = true;
				break;
			}
			if(dup)	continue;
			stack.push_back(N.NodeNumber);
			T.push_back(N.NodeNumber);
			temp.push_back(T);
			T.pop_back();
		}
	}

	//path print debugging
	/*
	for(auto e1 : pathlist)
	{
		cout << "path : "; 
		for(auto e2 : e1) cout << e2 << " ";
		cout << endl;
	}*/
	
	//sort path
	sort(pathlist.begin(), pathlist.end());

	//shuffle path to garuntee randomness, but keep path length order.
        vector<vector<vector<int>>> pathBasket;
	bool st = true;
	for(auto p : pathlist)
	{
		if(st)
		{
			vector<vector<int>> b;
			b.push_back(p);
			pathBasket.push_back(b);
			st = false;
		}
		else
		{
			if(p.size() == pathBasket[pathBasket.size()-1][0].size())
			{
				pathBasket[pathBasket.size()-1].push_back(p);
			}
			else
			{
				vector<vector<int>> b;
				b.push_back(p);
				pathBasket.push_back(b);
			}
		}
	}
	while(pathlist.size()>0)	pathlist.pop_back();
	unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
	for(auto b : pathBasket)
	{
		std::shuffle(b.begin(),b.end(),std::default_random_engine(seed));
		for(auto p : b)	pathlist.push_back(p);
	}

	//traversal
	vector<int> node_result;

	LweSample *t = new_gate_bootstrapping_ciphertext(EK->params);

	for(auto p : pathlist)
	{
		bootsCONSTANT(t,1,EK);
		for(int i = 0; i < p.size(); i++)
		{
			int e = p[i];
			node_result.push_back(e);
			nodeList n = findNode(G,e);
			
			bootsAND(n.node->T, t, t, EK);

			if (i == p.size()-1)	continue;
			for(auto N : *(n.node->Neighbors))
			{
				if(N.NodeNumber == p[i+1])
				{
					bootsAND(N.T, t, t, EK);
					break;
				}	
			}
			if(bootsSymDecrypt(t,PK) == 0)	break;
		}
		if(bootsSymDecrypt(t,PK) == 0)	break;
	}
	delete_gate_bootstrapping_ciphertext(t);

	vector<int>::iterator ip;
	int count;
	sort(node_result.begin(), node_result.end());
	count = std::distance(node_result.begin(), std::unique(node_result.begin(),node_result.end()));
	return count;
	
}
