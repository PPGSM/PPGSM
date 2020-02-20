// homomorphic libraries & Basic C++ libraries 
#include <iostream>
#include "seal/seal.h"
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <ctime>
#include <random>
#include <set>
#include <fstream>

// Header from graph processing objects.
#include "structure/struct.h"
#include "utility/graph_client.h"
#include "function.h"
#include "structure/graph.h"
#include "utility/AdvSearch.h"

using namespace std;
using namespace seal;

bool cmp3(const pair<int, int> &a, const pair<int, int> &b){
    return a.second < b.second;
}

int main(int argc, char **argv){

	clock_t start_, end_;

/* SEAL setting */
	start_ = clock(); 
	EncryptionParameters prms(scheme_type::CKKS);
//	size_t poly_modulus_degree = 8192;
	size_t poly_modulus_degree = 16384;
	prms.set_poly_modulus_degree(poly_modulus_degree);
//	prms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));
	prms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 40, 40, 40, 40, 60}));
	
	double scale = pow(2.0, 40);
	auto context = SEALContext::Create(prms);
	KeyGenerator keygen(context);
	auto public_key = keygen.public_key();
    	auto secret_key = keygen.secret_key();
    	auto relin_keys = keygen.relin_keys();
    	Encryptor encryptor(context, public_key);
    	Evaluator evaluator(context);
    	Decryptor decryptor(context, secret_key);
	CKKSEncoder encoder(context);
	size_t slot_count = encoder.slot_count();
	end_ = clock();
	cout <<"SEAL: " <<(double)(end_ - start_) / CLOCKS_PER_SEC <<endl;

/* TFhe setting */
	start_ = clock();
        //generate a keyset
        const int minimum_lambda = 110;
        TFheGateBootstrappingParameterSet* params = new_default_gate_bootstrapping_parameters(minimum_lambda);
        //generate a random key
        uint32_t seed[] = { 314, 1592, 657 };
        tfhe_random_generator_setSeed(seed,3);
        TFheGateBootstrappingSecretKeySet* key = new_random_gate_bootstrapping_secret_keyset(params);
	end_ = clock();
	cout <<"TFHE: " <<(double)(end_ - start_) / CLOCKS_PER_SEC <<endl;

/* main part */
	struct Graph G;	
	start_ = clock();	
	int sP = 0;
	MakeGraph(G, argv[1], argv[2], argv[3], key, public_key, context);
	end_ = clock();
	cout <<"make graph: " <<(double)(end_ - start_) / CLOCKS_PER_SEC <<endl;

/*
	// compare normal case, random adding case, heuristic adding case
	srand(time(NULL));	
	double tDB = 0, tDFS = 0, tBFS = 0;
	int s = G.node->size();
	double cost=0, searchingTime = 0;
	clock_t start,end;

	//make source node set
	int sourceNum = 0;
        set<int> sourceNodeSet;
        degree inOutDeg = getDegree(G);

        vector<int> table = totalDegree(inOutDeg);
        vector<pair<int,int>> nodeDeg;
        for(int i=0;i<s;i++){
                nodeDeg.push_back(make_pair(i,table[i]));
        }
        sort(nodeDeg.begin(), nodeDeg.end(), cmp3);

        int index = 0, temp_index = 0;
        double Table[s];
//	int left_size = s;
	int left_size = (int)(0.1 * (double)s);
	if(left_size == 0){
		left_size = 1;
	}
        index = 0;
	int tmp = (int)(0.1 * (double)s);
	if(tmp==0){
		tmp=1;
	}

	bool graphFull = false;

	while(sourceNodeSet.size() <= tmp)  // 10% of total nodes
//	while(sourceNodeSet.size() < s)
        {
		if(index == s){
			graphFull = true;
			break;
		}
		if(nodeDeg[index].second==0){
			index++;
			continue;
		}
		else{
	                vector<int> temp;
	                int temp_degree = nodeDeg[index].second;
	                while(temp_degree == nodeDeg[index].second){
	                        int source = nodeDeg[index].first;
	                        temp.push_back(source);
	                        index ++;
	                }

	                if(temp.size() < left_size){
	                        for(int i=0;i<temp.size();i++){
	                                sourceNodeSet.insert(temp[i]);
	                        }
	                        left_size = left_size - temp.size();
	                        temp.clear();
	                }
	                else{
	                        unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
	                        std::shuffle(temp.begin(), temp.end(), std::default_random_engine(seed));
	                        for(int i=0;i<left_size;i++){
	                                sourceNodeSet.insert(temp[i]);
	                        }
	                        break;
	                }
		}
        }
*/
/*
	//check source node set
	cout << "source node set: ";
        for(set<int>::iterator it = sourceNodeSet.begin(); it != sourceNodeSet.end(); ++it){
                cout << *it <<" ";
        }
        cout <<endl;
*/

/*
	int source = rand() % s;
	while(sourceNodeSet.find(source)==sourceNodeSet.end()){
		source = rand() % s;
	}

	int destination = rand() % s;
	if(graphFull == false){
		while(1){
			std::set<int>::iterator it = sourceNodeSet.find(destination);			
			if(it != sourceNodeSet.end()){
				destination = rand() % s;
			}
			else{
				break;
			}
		}
	}
	else{
		while(destination == source){
			destination = rand()%s;
		}
	}

*/
/*
	//compare DFS and restricted DFS.
	int source = rand() % s;
	int destination = rand() % s;
	while(destination == source){
		destination = rand() % s;
	}
	double DFStime=0, restrictedDFStime=0;
	start = clock();
	int dfs = DFSattack(G, source, destination, cost, B, key, &key->cloud);
	end = clock();
	DFStime = (double)(end - start);
	start = clock();
	int restricted_dfs = restrictedDFSattack(G, source, destination, cost, B, key, &key->cloud);
	end = clock();
	restrictedDFStime = (double)(end - start);

	if(dfs != 0){
		cout << dfs <<"\t" <<restricted_dfs <<"\t" <<DFStime <<"\t" <<restrictedDFStime <<endl;
	}
*/
/*
	vector<double> C;
	for(int i=0;i<s;i++){
		C.push_back(0);
	}
	double normal_cost = 0, normal_searchingTime = 0, random_cost = 0, random_searchingTime = 0, random_final_cost = 0, random_final_searchingTime = 0, heur_cost = 0, heur_execTime = 0, heur_cost2 = 0, heur_execTime2 = 0;

	double ran_cost[10]={0,}, ran_final_cost[10]={0,};;
	int pos_case[10]={0,};

	int possible_case = 0, possible_case1 = 0, possible_case2 = 0, possible_case3=0;

	for(set<int>::iterator it = sourceNodeSet.begin(); it != sourceNodeSet.end(); ++it){
		int source = *it;

//	for(int cnt = 0; cnt < 10; cnt++){
//		int source = rand()%s;
//		while(sourceNodeSet.find(source)==sourceNodeSet.end()){
//      	        source = rand() % s;
//	        }

		int destination = rand() % s;
		if(graphFull == false){
	              	while(1){
                    	std::set<int>::iterator it = sourceNodeSet.find(destination);
	                        if(it != sourceNodeSet.end()){
	                                destination = rand() % s;
	                        }
	                        else{
	                                break;
	                        }
	                }
	        }
	      	else{
	                while(destination == source){
	                        destination = rand()%s;
			} 
	        }
*/
//		cout <<"source: " <<source <<"\t" <<"destination: " <<destination <<endl;
/*		
        	vector<double> betCen = someBetweennessCen(G, &key->cloud, destination, sourceNodeSet);
		for(int i=0;i<s;i++){
	                cout <<betCen[i] <<"\t";
	        }
	        cout <<endl;
	
	   	vector<double> weightedPathBetCen = weightedPathBetweennessCentrality(G, &key->cloud, source, destination);
	        for(int i=0;i<s;i++){
	                cout <<weightedPathBetCen[i] <<"\t";
	        }
	        cout <<endl;
	
	        vector<double> pathBetCen = allPathBetweennessCentrality(G, &key->cloud, source, destination);
	        for(int i=0;i<s;i++){
	                cout <<pathBetCen[i] <<"\t";
	        }
	        cout <<endl;
	        for(int i=0;i<s;i++){
	                cout <<minCut(G, i, destination, &key->cloud) - 1 <<"\t";
	        }
	        cout <<endl;
*/
/*
		vector<double> B = someBetweennessCen(G, &key->cloud, destination, sourceNodeSet);
//		cout <<"Betweenness Centrality" <<endl;
//		for(int k=0;k<s;k++){
//			cout <<k <<". " <<B[k] <<endl;
//		}

 		int nodeNum = (int)(0.1	*(double)s);
		if(nodeNum ==0){
                        nodeNum=1;
                }
	//original case
//		cout <<"start normal case" <<endl;
//		countTotalPath(G, source, destination);
		for(int k=0;k<100;k++){
			int result = 0;
			start = clock();
			result = DFSattack(G, source, destination, tDFS, C, key, &key->cloud);
//			result = restrictedDFSattack(G, source, destination, tDFS, B, key, &key->cloud);
			if(result != 0){
				possible_case ++;
			}
			end = clock();
			normal_cost += (double)result;
			normal_searchingTime += (double)(end-start) / CLOCKS_PER_SEC;
		}
//		cout <<"Normal Case" <<endl;
//		cout << normal_cost <<"\t";
//		cout << normal_searchingTime <<endl <<endl;
//		cout <<"end normal case" <<endl;

	//random case
//		cout <<"start random case" <<endl;
		struct Graph tempG;
		MakeGraph(tempG, argv[1], argv[2], argv[3], key, public_key, context);
//		addRandomlyOnlyEdges(tempG, 1, &key->cloud);
		for(int a=0;a<nodeNum;a++){
			addRandomlyEdgesNodes(tempG, 1, G.node->size(), &key->cloud, key, public_key, context);
		}
//		cout <<"adding randomly finished" <<endl;
//		countTotalPath(tempG, source, destination);

		for(int a=0;a<100;a++){
			int result = 0;
			start = clock();
			result = DFSattack(tempG, source, destination, tDFS, C, key, &key->cloud);
//			result = restrictedDFSattack(tempG, source, destination, tDFS, B, key, &key->cloud);
			if(result != 0){
				possible_case1 ++;
			}
			end = clock();
			random_cost += (double)result;
			random_searchingTime += (double)(end-start) / CLOCKS_PER_SEC;
		}
//		cout <<i <<"--" <<j <<"\t";
//		cout << random_cost <<"\t";
//		random_final_cost += random_cost;
//		cout <<random_searchingTime <<endl<<endl;
//		random_final_searchingTime += random_searchingTime;
//		random_cost = 0, random_searchingTime = 0;
		//cout <<"Random add case" <<endl;
		//cout << random_cost / 10 <<"\t";
		//cout << random_searchingTime / 10 <<endl <<endl;		
//		cout <<"end random case" <<endl<<endl;

	//heuristic case
//		cout <<"start heuri 1 case" <<endl;
		struct Graph tempG2;
		MakeGraph(tempG2, argv[1], argv[2], argv[3], key, public_key, context);	
		start = clock();
		heuristicAddNodes(tempG2, destination, nodeNum, B, &key->cloud, key ,public_key, context);
		end = clock();
//		cout <<"Add dummy node finished" <<endl;
//		countTotalPath(tempG2, source, destination);
	
		for(int k=0;k<100;k++){
			int result = 0;
			result = DFSattack(tempG2, source, destination, tDFS, C, key, &key->cloud);
//			result = restrictedDFSattack(tempG2, source, destination, tDFS, B, key, &key->cloud);
			if(result != 0){
				possible_case2++;
			}
			heur_cost += (double)result;
			heur_execTime += (double)(end-start) / CLOCKS_PER_SEC;
		}
//		cout <<"Heuristic add case" <<endl;
//		cout << heur_cost<<"\t";
//		cout << heur_searchingTime<<endl<<endl;
//		cout <<"end heuri1 case" <<endl<<endl;

	//heuristic case2
//		cout <<"start heuri 2 case" <<endl;
                struct Graph tempG3;
                MakeGraph(tempG3, argv[1], argv[2], argv[3], key, public_key, context);
		start = clock();
                heuristicAddNodes2(tempG3, destination, nodeNum, B, &key->cloud, key ,public_key, context);
		end = clock();
                for(int k=0;k<100;k++){
                        int result = 0;
                        result = DFSattack(tempG3, source, destination, tDFS, B, key, &key->cloud);
//			result = restrictedDFSattack(tempG3, source, destination, tDFS, B, key, &key->cloud);
                        if(result != 0){
                                possible_case3++;
                        }
                        heur_cost2 += (double)result;
                        heur_execTime2 += (double)(end-start) / CLOCKS_PER_SEC;
                }
//		cout <<"Heuristic add case 2" <<endl;
//		cout << heur_cost2<<"\t";
//		cout << heur_searchingTime2<<endl<<endl;
//		cout <<"end heuri 2 case" <<endl<<endl;
	}	

	if(possible_case != 0){
	//	cout <<"Normal Case" <<endl;
		cout << normal_cost / possible_case <<"\t";
	//	cout << normal_searchingTime / sourceNodeSet.size() <<endl <<endl;	
		
	//	cout <<"Random add case" <<endl;
		cout << random_cost / possible_case1 <<"\t";
	//	cout << random_searchingTime / (10 * sourceNodeSet.size()) <<endl <<endl;
		
	//	cout <<"Heuristic add case" <<endl;
		cout << heur_cost / possible_case2 <<"\t";
	
	//      cout <<"Heuristic add case" <<endl;
		cout << heur_cost2 / possible_case3 <<endl;
		
//		cout << heur_execTime / sourceNodeSet.size() <<"\t";
//		cout << heur_execTime2 / sourceNodeSet.size() <<endl;
	}
*/
	return 0;
}
