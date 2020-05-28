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
	size_t poly_modulus_degree = 8192;
//	size_t poly_modulus_degree = 32768;
	prms.set_poly_modulus_degree(poly_modulus_degree);
	prms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));
//	prms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 40, 40, 40, 40, 40, 40, 60}));
	
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

	struct degree nodeDegree = getDegree(G);
	vector<struct degInfo> Vin = nodeDegree.Vin;
//	vector<struct degInfo> Vout = nodeDegree.Vout;
/*
	cout <<"In-degree: " <<'\t';
	for(int i=0;i<G.node->size();i++){
		cout <<Vin[i].Degree <<'\t';
	}
	cout <<endl;
*/
//	cout <<"Out-degree: " <<'\t';
//	for(int i=0;i<G.node->size();i++){
//		cout <<Vout[i].Degree <<'\t';
//	}
//	cout <<endl;

	int startPoint = 0;
        int endPoint = G.node->size()-1;
/*
for(int i=0;i<30;i++){
	MakeGraph(G, argv[1], argv[2], argv[3], key, public_key, context);
	srand(time(NULL));
	sP = rand() % G.node->size();
        int eP = rand() % G.node->size();
	while(eP == sP){
		eP = rand() % G.node->size();
	}
	int target = rand() % G.node->size();
        while(target == sP || target == eP){
                target = rand() % G.node->size();
        }

        cout <<sP <<", " <<eP <<", " <<target <<endl;

	//find all possible path(real and dummy both) with attack cost and risk
	start_ = clock();
	cout <<"*** Probing result ***" <<endl;
        init_probe(G, sP, eP, &key->cloud, key, evaluator, relin_keys, public_key, context, secret_key);
        end_ = clock();
        cout <<"total time to probing: " <<(double)(end_ - start_) / CLOCKS_PER_SEC <<endl <<endl;
	

	//find a mincut of the graph
//	cout <<"------ In test, path length means number of nodes of path ------" <<endl;
	cout <<"*** Shortest path length ***" <<endl;
        start_ = clock();
	int minLen = minCut(G,sP,eP,&key->cloud);
        end_ = clock();
	cout <<"total time to minCut: " <<(double)(end_ - start_) / CLOCKS_PER_SEC <<endl;
	cout <<"Length of the shortest path: " <<minLen <<endl <<endl;	
	

	//find MPL(mean path length)
	cout <<"*** Mean path length ***" <<endl;
	start_ = clock();
        mpl(G,sP,eP,&key->cloud, evaluator, relin_keys, public_key, context);
      	end_ = clock();
      	cout <<endl;
	cout <<"total time to MPL: " <<(double)(end_ - start_) / CLOCKS_PER_SEC <<endl <<endl;

	//pruning
	cout <<"*** Pruning (1 node) ***" <<endl;
	start_ = clock();
        prune(G,nodeDegree,1);
        end_ = clock();
        cout <<"time to pruning 1 node: " <<(double)(end_ - start_) / CLOCKS_PER_SEC <<endl <<endl;
	delete_graph(G);
*/
	/*//////////////
	//calculate independent attack success probability
        start_ = clock();
        PrAtkSuccess(G, sP, eP, &key->cloud, key, evaluator, relin_keys, public_key, context, secret_key);
        end_ = clock();
cout <<"Ind prob: " <<(double)(end_ - start_) / CLOCKS_PER_SEC <<endl;
       
	//calculate cumulative probability of attack success
        start_ = clock();
        cumulPrAtkSuccess(G, sP, evaluator, relin_keys, public_key, context, secret_key);
        end_ = clock();
        cout <<"Cum prob: " <<(double)(end_ - start_) / CLOCKS_PER_SEC <<endl;

        //calculate return on investment
        start_ = clock();
        returnInvestment(G, sP, eP, target, &key->cloud, key, evaluator, relin_keys, public_key, context, secret_key);
        end_ = clock();
        cout <<"ROI: " <<(double)(end_ - start_) / CLOCKS_PER_SEC <<endl;
	delete_graph(G);
	*/////////////
	
//	}
















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
	int left_size = (int)(1 * (double)s);		//change--source node set size
	if(left_size == 0){
		left_size = 1;
	}
	int tmp = left_size;

	bool graphFull = false;

	while(sourceNodeSet.size() <= tmp)
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


	//check source node set
	cout << "source node set: ";
        for(set<int>::iterator it = sourceNodeSet.begin(); it != sourceNodeSet.end(); ++it){
                cout << *it <<" ";
        }
        cout <<endl;



	vector<double> C;
	for(int i=0;i<s;i++){
		C.push_back(0);
	}
	double normal_cost = 0, normal_searchingTime = 0, random_cost = 0, random_searchingTime = 0, random_final_cost = 0, random_final_searchingTime = 0, heur_cost = 0, heur_execTime = 0, heur_cost2 = 0, heur_execTime2 = 0;
	double normal_cost_s = 0, normal_searchingTime_s = 0, random_cost_s = 0, random_searchingTime_s = 0, random_final_cost_s = 0, random_final_searchingTime_s = 0, heur_cost_s = 0, heur_execTime_s = 0, heur_cost2_s = 0, heur_execTime2_s = 0;

	double ran_cost[10]={0,}, ran_final_cost[10]={0,};;
	int pos_case[10]={0,};

	int possible_case = 0, possible_case1 = 0, possible_case2 = 0, possible_case3=0;
	int possible_case_s = 0, possible_case1_s = 0, possible_case2_s = 0, possible_case3_s=0;

//	for(set<int>::iterator it = sourceNodeSet.begin(); it != sourceNodeSet.end(); ++it){
//		int source = *it;

//	for(int cnt = 0; cnt < 10; cnt++){
//		int source = rand()%s;
//		while(sourceNodeSet.find(source)==sourceNodeSet.end()){
//      	        source = rand() % s;
//	        }

	int source = rand() % s;
	int destination = rand() % s;
		/*
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
		*/
	 while(destination == source){
		 cout <<destination <<endl;
	 	 destination = rand()%s;
	 } 
	        //}

	cout <<"source: " <<source <<"\t" <<"destination: " <<destination <<endl;
	int minLen = minCut(G, source, destination, &key->cloud);
	vector<double> B = someBetweennessCen(G, &key->cloud, destination, sourceNodeSet);
	cout <<"mincut: " <<minLen <<endl;
//		cout <<"Betweenness Centrality" <<endl;
//		for(int k=0;k<s;k++){
//			cout <<k <<". " <<B[k] <<endl;
//		}

	int nodeNum = (int)(0.1	*(double)s);	//change--number of added nodes
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
		int result_s = shortestPathattack(G,source,destination,&key->cloud,key);
		if(result != 0){
			possible_case ++;
		}
		if(result_s!= 0){
			possible_case_s++;
		}
		end = clock();
		normal_cost += (double)result;
		normal_cost_s += (double)result_s;
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
	for(int a=0;a<nodeNum;a++){
		addRandomlyEdgesNodes(tempG, 1, G.node->size(), &key->cloud, key, public_key, context);
	}
//	cout <<"adding randomly finished" <<endl;
//	countTotalPath(tempG, source, destination);
	for(int a=0;a<100;a++){
		int result = 0;
		start = clock();
		result = DFSattack(tempG, source, destination, tDFS, C, key, &key->cloud);
			
		int result_s = shortestPathattack(tempG,source,destination,&key->cloud,key);
		if(result != 0){
			possible_case1 ++;
		}
		if(result_s!= 0){
			possible_case1_s++;
		}
		end = clock();
		random_cost += (double)result;
		random_cost_s += (double)result_s;
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
	delete_graph(tempG);

	//heuristic case
//		cout <<"start heuri case" <<endl;
	struct Graph tempG2;
	MakeGraph(tempG2, argv[1], argv[2], argv[3], key, public_key, context);	
	start = clock();
	for(int k=0;k<nodeNum;k++){
		B = someBetweennessCen(tempG2, &key->cloud, destination, sourceNodeSet);
		heuristicAddNodes(tempG2, destination, 1, B, &key->cloud, key ,public_key, context);
	}
	end = clock();
//		cout <<"Add dummy node finished" <<endl;
//		countTotalPath(tempG2, source, destination);

	for(int k=0;k<100;k++){
		int result = 0;
		result = DFSattack(tempG2, source, destination, tDFS, C, key, &key->cloud);
		int result_s = shortestPathattack(tempG2,source,destination,&key->cloud,key);
		if(result != 0){
			possible_case2++;
		}
		if(result_s!= 0){
			possible_case2_s++;
		}
		heur_cost += (double)result;
		heur_cost_s += (double)result_s;
		heur_execTime += (double)(end-start) / CLOCKS_PER_SEC;
	}
//		cout <<"Heuristic add case" <<endl;
//		cout << heur_cost<<"\t";
//		cout << heur_searchingTime<<endl<<endl;
//		cout <<"end heuri case" <<endl<<endl;
	delete_graph(tempG2);

	//heuristic case2
//		cout <<"start heuri 2 case" <<endl;
        struct Graph tempG3;
        MakeGraph(tempG3, argv[1], argv[2], argv[3], key, public_key, context);
	start = clock();
	for(int k=0;k<nodeNum;k++){
		nodeDegree = getDegree(tempG3);
		Vin = nodeDegree.Vin;
                heuristicAddNodesDB(tempG3, destination, 1, Vin, &key->cloud, key ,public_key, context);
	}
	end = clock();
        for(int k=0;k<100;k++){
		int result = 0;
                result = DFSattack(tempG3, source, destination, tDFS, B, key, &key->cloud);
		int result_s = shortestPathattack(tempG3,source,destination,&key->cloud,key);
                if(result != 0){
			possible_case3++;
                }
		if(result_s!= 0){
			possible_case3_s++;
		}
                heur_cost2 += (double)result;
		heur_cost2_s += (double)result_s;
                heur_execTime2 += (double)(end-start) / CLOCKS_PER_SEC;
	}
//		cout <<"Heuristic add case 2" <<endl;
//		cout << heur_cost2<<"\t";
//		cout << heur_searchingTime2<<endl<<endl;
//		cout <<"end heuri 2 case" <<endl<<endl;
	delete_graph(tempG3);
//	}	
	if(possible_case != 0){
	//	cout <<"Normal Case" <<endl;
		cout << normal_cost / possible_case <<"\t";
	//	cout << normal_searchingTime / sourceNodeSet.size() <<endl <<endl;	
		
	//	cout <<"Random add case" <<endl;
		cout << random_cost / possible_case1 <<"\t";
	//	cout << random_searchingTime / (10 * sourceNodeSet.size()) <<endl <<endl;
		
	//	cout <<"Heuristic add case" <<endl;
		cout << heur_cost / possible_case2 <<"\t";
	//	cout << endl;	
	//      cout <<"Heuristic2 add case" <<endl;
		cout << heur_cost2 / possible_case3 <<endl;
		
//		cout << heur_execTime / sourceNodeSet.size() <<"\t";
//		cout << heur_execTime2 / sourceNodeSet.size() <<endl;
	}
	if(possible_case_s != 0){
        //      cout <<"Normal Case" <<endl;
                cout << normal_cost_s / possible_case_s <<"\t";
        //      cout << normal_searchingTime / sourceNodeSet.size() <<endl <<endl;

        //      cout <<"Random add case" <<endl;
                cout << random_cost_s / possible_case1_s <<"\t";
        //      cout << random_searchingTime / (10 * sourceNodeSet.size()) <<endl <<endl;

        //      cout <<"Heuristic add case" <<endl;
                cout << heur_cost_s / possible_case2_s <<"\t";
        //      cout << endl;
        //      cout <<"Heuristic2 add case" <<endl;
                cout << heur_cost2_s / possible_case3_s <<endl;

//              cout << heur_execTime / sourceNodeSet.size() <<"\t";
//              cout << heur_execTime2 / sourceNodeSet.size() <<endl;
        }
	return 0;
}
