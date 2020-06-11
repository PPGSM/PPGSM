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
#include "structure/graph.h"
#include "utility/AdvSearch.h"
#include "cmath"

using namespace std;
using namespace seal;

int main(int argc, char **argv){
	clock_t start_, end_;	//for measuring execution time

				//////////////////
				// SEAL setting //
				//////////////////
	start_ = clock(); 
	EncryptionParameters prms(scheme_type::CKKS);
/*
we change initial parameters for incresing a number of multiplications because of approximation with Taylor's expansion
*/

//	size_t poly_modulus_degree = 8192;
	size_t poly_modulus_degree = 32768;
	prms.set_poly_modulus_degree(poly_modulus_degree);
//	prms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));
	prms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 40, 40, 40, 40, 40, 40, 60}));
	
	double scale = pow(2.0, 40);
	auto context = SEALContext::Create(prms);
	KeyGenerator keygen(context);
	CKKSEncoder encoder(context);
	auto public_key = keygen.public_key();
    	auto secret_key = keygen.secret_key();
    	auto relin_keys = keygen.relin_keys();
	GaloisKeys gal_keys = keygen.galois_keys();
    	Encryptor encryptor(context, public_key);
    	Evaluator evaluator(context);
    	Decryptor decryptor(context, secret_key);	//decryptor is only used for check result.
	size_t slot_count = encoder.slot_count();
	end_ = clock();
	cout <<"SEAL setting time(s): " <<(double)(end_ - start_) / CLOCKS_PER_SEC <<endl;


				//////////////////
				// TFhe setting //		
				//////////////////
	start_ = clock();
        //generate a keyset
        const int minimum_lambda = 110;
        TFheGateBootstrappingParameterSet* params = new_default_gate_bootstrapping_parameters(minimum_lambda);
        //generate a random key
        uint32_t seed[] = { 314, 1592, 657 };
        tfhe_random_generator_setSeed(seed,3);
        TFheGateBootstrappingSecretKeySet* key = new_random_gate_bootstrapping_secret_keyset(params);
	end_ = clock();
	cout <<"TFHE setting time(s): " <<(double)(end_ - start_) / CLOCKS_PER_SEC <<endl;

				///////////////
				// main part //
				///////////////
	// receive info to analyze GSM
        int startPoint, endPoint;
        cout <<"Enter start point and end point: ";
        cin >> startPoint >>endPoint;
		
			/* process to construct a GSM */
	vector<string> OSList =  loadOSlist("table/OSlist");
	queryDataByFile(argv[2],OSList, encoder, encryptor);

	//client-side
	struct Graph G;
        MakeGraph(G, argv[1], argv[2], argv[3], key, public_key, context);
        createTopology(G, &key->cloud);
        delete_graph(G);

	//server-side
	GSMCreation(G, context, gal_keys, evaluator, relin_keys, &key->cloud);
			
		/* Independent probability of attack success */
/*
	start_ = clock();	
	PrAtkSuccess(G,startPoint,endPoint,&key->cloud,key,evaluator,relin_keys,public_key,context,secret_key);
	end_ = clock();
	cout <<"Independent attack success probabiltiy calculation time: " <<((double)(end_ - start_) / CLOCKS_PER_SEC) <<endl;
*/

			/* Return on Investment (ROSI) */
/*
	int ROItarget;
	cout <<"Enter target node for compute ROSI: ";
	cin >>ROItarget;
	
	start_ = clock();	
	returnInvestment(G,startPoint,endPoint,ROItarget, &key->cloud, key, evaluator, relin_keys, public_key, context, secret_key);
	end_ = clock();
	cout <<"ROSI calculation time: " <<((double)(end_ - start_) / CLOCKS_PER_SEC) <<endl;
*/

			/* Risk & attack cost (probe) */
/*
	start_ = clock();	
	init_probe(G,startPoint,endPoint,&key->cloud,key,evaluator,relin_keys,public_key,context,secret_key);
	end_ = clock();
	cout <<"Attack cost & risk calculation time: " <<((double)(end_ - start_) / CLOCKS_PER_SEC) <<endl;
*/

			/* Cumulative attack success */
/*
	start_ = clock();	
	cumulPrAtkSuccess(G,startPoint,evaluator,relin_keys,public_key,context,secret_key);
	end_ = clock();
	cout <<"Cumulative attack cost calculation time: " << ((double)(end_ - start_) / CLOCKS_PER_SEC) <<endl;
*/

			/* Shortest path length (SPL) */
/*
	start_ = clock();	
	minLength(G,startPoint,endPoint,&key->cloud);
	end_ = clock();
	cout <<"SPL calculation time: " <<((double)(end_ - start_) / CLOCKS_PER_SEC) <<endl;
*/

			/* Mean path length (MPL) */
/*
	start_ = clock();	
	mpl(G,startPoint,endPoint,&key->cloud,evaluator,relin_keys,public_key,context);
	end_ = clock();
	cout <<"MPL calculation time: " <<((double)(end_ - start_) / CLOCKS_PER_SEC) <<endl;
*/

	delete_graph(G);
}

