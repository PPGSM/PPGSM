#include "struct.h"
#include "../function.h"
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

static bool operator <(degInfo &a, degInfo &b){
        return a.Degree < b.Degree;
}

/////////////		functions used in evaluating a graph		////////////////

//find all possible path between source node and destination node with attack cost and risk
int num = 1;

void probe(struct Graph& G, Ciphertext cost, Ciphertext risk, struct nodeList &N, LweSample* Tmp, vector<int> path, int dest, const TFheGateBootstrappingCloudKeySet* EK, Evaluator &eval, auto &relin_keys, std::shared_ptr<seal::SEALContext> context){
	N.visited = true;
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
		cout <<"Path " <<num <<"." <<"\t";
		num++;
		
		for(auto P : path)
		{
			cout << P+1 << " ";
		}
		cout << endl;
        }
        else{
		for(iter = N.node->Neighbors->begin(); iter != N.node->Neighbors->end(); ++iter){
			list<struct nodeList>::iterator iter2;
			for(iter2 = G.node->begin(); iter2 != G.node->end(); ++iter2){
				if((*iter).NodeNumber == (*iter2).node->NodeNumber && (*iter2).visited == false){
					LweSample *Temp = new_gate_bootstrapping_ciphertext(EK->params);
					bootsAND(Temp,Tmp,(*iter).T,EK);
			probe(G, cost, risk, (*iter2), Temp, path, dest, EK, eval, relin_keys, context);
					(*iter2).visited = false;
				}
			}
		}
	}
	N.visited = false;
}

//initial function to start probe
void init_probe(struct Graph& G, int startNumber, int destNumber, const TFheGateBootstrappingCloudKeySet* EK, Evaluator &eval, seal::RelinKeys& relin_keys, seal::PublicKey public_key, std::shared_ptr<seal::SEALContext> context){
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

		probe(G, cost, risk, inode, T, path, destNumber, EK, eval,relin_keys, context);
		delete_gate_bootstrapping_ciphertext(T);
		break;
	}
}

//find a length of the shortest path
void probeMinCut(struct Graph& G, struct nodeList& N, vector<int> path, int &Length, int dest, const TFheGateBootstrappingCloudKeySet* EK){
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
						probeMinCut(G, (*iter2), path, Length, dest, EK);
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
	int MinLength = 1000000;                //just a large value.
	list<struct nodeList>::iterator iter;
	for(iter = G.node->begin(); iter != G.node->end(); ++iter){
		(*iter).visited = false;
	}
	for(iter = G.node->begin(); (*iter).node->NodeNumber != startNumber; ++iter);
	vector<int> P;
	probeMinCut(G, *iter, P, MinLength, destNumber, EK);
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
	cout <<"MPL: " <<result <<endl;

	int shortestLength = minLength(G, startNumber, destNumber, EK);
	init_probeShortestPath(G, startNumber, destNumber, shortestLength, result, EK, eval, relin_keys, public_key, context);	
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

//a function that finds a specific node using nodeNumber
struct nodeList findNode(struct Graph &G, int nodeNumber){
	list<struct nodeList>::iterator iter;
	for(iter = G.node->begin(); (*iter).node->NodeNumber != nodeNumber; ++iter);
	return (*iter);
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
	list<struct nodeList>::iterator iter;
	for(list<nodeList>::iterator N = G.node->begin(); N != G.node->end(); ++N){
		int lenVt = Vt.size();
		
		// Deleting edges.
		for(list<Neighbor>::iterator Nn = (*N).node->Neighbors->begin();Nn != (*N).node->Neighbors->end(); ++Nn){
			for(auto e : Vt){
				if(e == Nn->NodeNumber){
					(*N).node->Neighbors->erase(Nn++);
					if(Nn == (*N).node->Neighbors->end())   break;
				}
			}
			if(Nn == (*N).node->Neighbors->end())   break;
		}
		
		//Deleting nodes.
		for(auto e : Vt){
			if(e == (*N).node->NodeNumber){
				printf("Node to delete : node number %d\n",((*N).node->NodeNumber) + 1);
				G.node->erase(N++);
				if(N == G.node->end())   return;
			}
		}
	}
}

void PrAtkSuccessProbe(struct Graph& G, Ciphertext &result, Ciphertext &base, Ciphertext logpr, struct nodeList& N, LweSample* Tmp, vector<int> path, vector<Ciphertext> &pathPr, int dest, const TFheGateBootstrappingCloudKeySet* EK, Evaluator &eval, seal::RelinKeys &relin_keys, std::shared_ptr<seal::SEALContext> context, seal::SecretKey secret_key){
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

		CKKSEncoder encoder(context);	
		Decryptor decryptor(context, secret_key);
		Plaintext plain_result;
		decryptor.decrypt(logpr, plain_result);
		vector<double> result;
		encoder.decode(plain_result, result);
//		cout << "logPr: " <<result[0] <<endl;

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
		PrAtkSuccessProbe(G, result, base, logpr, inode, T, P, pathPr, destNumber, EK,eval,relin_keys, context, secret_key);

		Plaintext ResultPr;
		encoder.encode(0,scale,ResultPr);
		Ciphertext finalResult;
		encryptor.encrypt(ResultPr, finalResult);
		Decryptor decryptor(context, secret_key);

		int size = pathPr.size();
		for(int i=0;i<size;i++){

			//test
			Plaintext plain_result1;
        	        decryptor.decrypt(pathPr[i], plain_result1);
                	vector<double> RST1;
	                encoder.decode(plain_result1, RST1);
	                cout <<"log(pr): " <<RST1[0] <<endl;

			Plaintext Temp0,Temp1,Temp2,Temp3,Temp4;
			encoder.encode(1, scale, Temp0);
			encoder.encode(1, scale, Temp1);
			encoder.encode(0.5, scale, Temp2);
			encoder.encode(0.16666, scale, Temp3);
			encoder.encode(0.041666, scale, Temp4);
			Ciphertext temp0, temp1, temp2, temp3, temp4, temp;
			encryptor.encrypt(Temp0,temp0);
			encryptor.encrypt(Temp1, temp1);
			encryptor.encrypt(Temp2, temp2);
			encryptor.encrypt(Temp3, temp3);
			encryptor.encrypt(Temp4, temp4);

			eval.multiply_inplace(temp1, pathPr[i]);
			eval.relinearize_inplace(temp1, relin_keys);
			eval.rescale_to_next_inplace(temp1);
			temp1.scale() = pow(2.0,40);

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

			eval.multiply_inplace(temp3, pathPr[i]);
			eval.relinearize_inplace(temp3, relin_keys);
			eval.rescale_to_next_inplace(temp3);
			temp3.scale() = pow(2.0,40);
			eval.multiply_inplace(temp3, temp);
			eval.relinearize_inplace(temp3, relin_keys);
			eval.rescale_to_next_inplace(temp3);
			temp3.scale() = pow(2.0,40);

			last_parms_id = temp3.parms_id();
			eval.mod_switch_to_inplace(temp0, last_parms_id);
			eval.mod_switch_to_inplace(temp1, last_parms_id);
			eval.mod_switch_to_inplace(temp2, last_parms_id);

			eval.add_inplace(temp0, temp1);
			eval.add_inplace(temp0, temp2);
			eval.add_inplace(temp0, temp3);

			//test
			Plaintext plain_result2;
	                decryptor.decrypt(temp0, plain_result2);
        	        vector<double> result2;
                	encoder.decode(plain_result2, result2);
	                cout << "pr: " <<result2[0] <<endl;
		
			Plaintext testTemp1,testTemp2,testTemp3;
                        encoder.encode(1, scale, testTemp1);
                        encoder.encode(0.5, scale, testTemp2);
                        encoder.encode(0.333333, scale, testTemp3);
                        Ciphertext secondtemp1, secondtemp2, secondtemp3, secondtemp;
			encryptor.encrypt(testTemp1, secondtemp1);
                        encryptor.encrypt(testTemp2, secondtemp2);
                        encryptor.encrypt(testTemp3, secondtemp3);

			eval.mod_switch_to_inplace(secondtemp1, last_parms_id);
			eval.mod_switch_to_inplace(secondtemp3, last_parms_id);
			eval.multiply_inplace(secondtemp1, temp0);
			eval.multiply_inplace(secondtemp3, temp0);
			eval.relinearize_inplace(secondtemp1, relin_keys);
			eval.relinearize_inplace(secondtemp3, relin_keys);
			eval.rescale_to_next_inplace(secondtemp1);
			eval.rescale_to_next_inplace(secondtemp3);
			secondtemp1.scale() = pow(2.0,40);
			secondtemp3.scale() = pow(2.0,40);

			eval.square(temp0, secondtemp);
			eval.relinearize_inplace(secondtemp, relin_keys);
			eval.rescale_to_next_inplace(secondtemp);
			secondtemp.scale() = pow(2.0, 40);
			last_parms_id = secondtemp.parms_id();
                        eval.mod_switch_to_inplace(secondtemp2, last_parms_id);
                        eval.mod_switch_to_inplace(secondtemp3, last_parms_id);

			eval.multiply_inplace(secondtemp2, secondtemp);
			eval.multiply_inplace(secondtemp3, secondtemp);
			eval.relinearize_inplace(secondtemp2, relin_keys);
			eval.relinearize_inplace(secondtemp3, relin_keys);
			eval.rescale_to_next_inplace(secondtemp2);
			eval.rescale_to_next_inplace(secondtemp3);
			secondtemp2.scale() = pow(2.0,40);
			secondtemp3.scale() = pow(2.0,40);

			last_parms_id = secondtemp3.parms_id();
			eval.mod_switch_to_inplace(secondtemp1, last_parms_id);
			eval.add_inplace(secondtemp1, secondtemp2);
			eval.add_inplace(secondtemp1, secondtemp3);

			//test
                        Plaintext plain_result3;
                        decryptor.decrypt(secondtemp1, plain_result3);
                        vector<double> result3;
                        encoder.decode(plain_result3, result3);
                        cout << "log(1-pr): " <<result3[0] <<endl;

			last_parms_id = secondtemp1.parms_id();
			eval.mod_switch_to_inplace(finalResult, last_parms_id);
			eval.add_inplace(finalResult, secondtemp1);	
		}
			//test
                        Plaintext plain_result0;
                        decryptor.decrypt(finalResult, plain_result0);
                        vector<double> result0;
                        encoder.decode(plain_result0, result0);
                      cout << "result: " <<result0[0] <<endl;

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

	for(int i=0;i<graphSize;i++){
		Ciphertext temp;
		Plaintext Temp;
		encoder.encode(0, scale, Temp);
		encryptor.encrypt(Temp,temp);
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
void returnInvestment(struct Graph& G, int startNumber, int destNumber, const TFheGateBootstrappingCloudKeySet* EK, const TFheGateBootstrappingSecretKeySet *PK, Evaluator &eval, seal::RelinKeys& relin_keys, seal::PublicKey public_key, std::shared_ptr<seal::SEALContext> context, seal::SecretKey secret_key){
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
//		LweSample *T = new_gate_bootstrapping_ciphertext(EK->params);
//		bootsCONSTANT(T, 1, EK);
		vector<int> path;
		vector<Ciphertext> diffRisk;
		diffRiskreturnOnInvestment(G, risk, inode, path, destNumber, diffRisk, EK, PK, eval, relin_keys, public_key, context, secret_key);
//		delete_gate_bootstrapping_ciphertext(T);
		
		for(int i=0;i<graphSize;i++){
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
		if(S==0){
			ret.push_back(0);
		}
		else{
			ret.push_back((double)(n-1)/(double)S);
		}
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
		createDummyNode(G, 10, 10, 0.2, -0.096, 1, 1, PK,public_key,context);
		int s = G.node->size();
		for(int a=0;a<1;a++){
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
                                int minLength = minCut(G, i, j, EK);

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


vector<double> allPathBetweennessCentrality(Graph& G, const TFheGateBootstrappingCloudKeySet* EK,int source, int dest){
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
		int sz = startNodeSet.size();
		int ran = rand() % sz;
		int startNodeNumber = startNodeSet[ran];
	
	//	cout <<"start node: " <<startNodeNumber <<endl;
	
		createDummyNode(G, 10, 10, 0.2, -0.096, 1, 1, PK, public_key, context);
	
	//	cout <<G.node->size()-1 <<endl;
		createDummyEdge(G, startNodeNumber, G.node->size()-1, true, EK);
		createDummyEdge(G, G.node->size()-1, startNodeNumber, true, EK);
//		cout <<"added edge: " <<startNodeNumber  <<"--" <<G.node->size()-1 <<endl;
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
		createDummyNode(G, 10, 10, 0.2, -0.096, 1, 1, PK, public_key, context);
		createDummyEdge(G, temp[i].first, G.node->size()-1, true, EK);
		createDummyEdge(G, G.node->size()-1, temp[i].first, true, EK);
//		cout <<"added edge: " <<temp[i].first <<"-----" <<G.node->size()-1 <<endl;
	}
}
