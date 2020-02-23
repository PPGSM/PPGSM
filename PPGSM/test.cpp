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

int main(int argc, char **argv){
	clock_t start_, end_;
	cout <<"*** settings ***" <<endl;
/* SEAL setting */
        start_ = clock();
        EncryptionParameters prms(scheme_type::CKKS);
//      size_t poly_modulus_degree = 8192;
        size_t poly_modulus_degree = 16384;
        prms.set_poly_modulus_degree(poly_modulus_degree);
//      prms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));
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
        cout <<"time to setting SEAL: " <<(double)(end_ - start_) / CLOCKS_PER_SEC <<"(s)" <<endl;

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
        cout <<"time to setting TFHE: " <<(double)(end_ - start_) / CLOCKS_PER_SEC <<"(s)" <<endl <<endl;	

	/* main part */
	//make an encrypted graph
        struct Graph G;
        start_ = clock();
        MakeGraph(G, argv[1], argv[2], argv[3], key, public_key, context);
        end_ = clock();
	cout <<"*** Create a graph ***" <<endl;
        cout <<"time to make graph: " <<(double)(end_ - start_) / CLOCKS_PER_SEC <<endl;
	cout <<"a size of graph: " <<G.node->size() <<endl;
	struct degree nodeDegree = getDegree(G);
	vector<struct degInfo> Vin = nodeDegree.Vin;
	vector<struct degInfo> Vout = nodeDegree.Vout;

	cout <<"In-degree: " <<'\t';
	for(int i=0;i<G.node->size();i++){
		cout <<Vin[i].Degree <<'\t';
	}
	cout <<endl;
	cout <<"Out-degree: " <<'\t';
        for(int i=0;i<G.node->size();i++){
                cout <<Vout[i].Degree <<'\t';
        }


	cout <<endl <<endl;

	int startPoint = 0;
        int endPoint = G.node->size()-1;
	//compute betweenness centrality and path betweenness centrality
	cout <<"*** Centralities ***" <<endl;
	vector<double> CC = closeness(G, &key->cloud);
	vector<double> BC = betweenness(G, &key->cloud);
        vector<double> PC = allPathBetweennessCentrality(G, &key->cloud, startPoint, endPoint);
	BC[0]=1;
        BC[G.node->size()-1]=1;
	cout <<"Closeness centrality:\t\t";
        for(int i=0;i<G.node->size();i++){
                printf("%.3lf	", CC[i]);
        }
        cout <<endl;

	cout <<"Betweenness centrality:\t\t";
	for(int i=0;i<G.node->size();i++){
		cout <<BC[i] <<'\t';
	}
	cout <<endl;
	
        cout <<"Path betweenness centrality:\t";
        for(int i=0;i<G.node->size();i++){
                cout <<PC[i] <<'\t';
        }
        cout <<endl <<endl;

	//find all possible path(real and dummy both) with attack cost and risk
        start_ = clock();
	cout <<"*** Probing result ***" <<endl;
        init_probe(G, startPoint, endPoint, &key->cloud, key, evaluator, relin_keys, public_key, context, secret_key);
        end_ = clock();
        cout <<"total time to probing: " <<(double)(end_ - start_) / CLOCKS_PER_SEC <<endl <<endl;

	//find a mincut of the graph
	cout <<"------ In test, path length means number of nodes of path ------" <<endl;
	cout <<"*** Shortest path length ***" <<endl;
        int minLen = minCut(G,0,G.node->size()-1,&key->cloud);
        cout <<"Length of the shortest path: " <<minLen <<endl <<endl;	

	//find MPL(mean path length)
	cout <<"*** Mean path length ***" <<endl;
        mpl(G,startPoint,endPoint,&key->cloud, evaluator, relin_keys, public_key, context);
        cout <<endl;

	//pruning
	cout <<"*** Pruning (1 node) ***" <<endl;
	start_ = clock();
        prune(G,nodeDegree,1);
        end_ = clock();
        cout <<"time to pruning 1 node: " <<(double)(end_ - start_) / CLOCKS_PER_SEC <<endl <<endl;

	
	MakeGraph(G, argv[1], argv[2], argv[3], key, public_key, context);
	//calculate independent probabilty of attack success
	cout <<"*** Probabilities of attack success ***" <<endl;
	start_ = clock();       
        PrAtkSuccess(G, startPoint, endPoint, &key->cloud, key, evaluator, relin_keys, public_key, context, secret_key);
        end_ = clock();
        cout <<"Time to calculate independent probability: " <<(double)(end_ - start_) / CLOCKS_PER_SEC <<endl <<endl;
	/*
        //calculate cumulative probability of attack success
        start_ = clock();
        cumulPrAtkSuccess(G, startPoint, evaluator, relin_keys, public_key, context, secret_key);
        end_ = clock();
        cout <<"Cum prob: " <<(double)(end_ - start_) / CLOCKS_PER_SEC <<endl;
	
	//calculate return onminvestment
        start_ = clock();
        returnInvestment(G, sP, G.node->size()-1, &key->cloud, key, evaluator, relin_keys, public_key, context, secret_key);
        end_ = clock();
        cout <<"ROI: " <<(double)(end_ - start_) / CLOCKS_PER_SEC <<endl;	
	*/
	return 0;
}
