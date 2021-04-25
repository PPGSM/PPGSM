// homomorphic libraries & Basic C++ libraries 
#include <iostream>
#include "seal/seal.h"
//#include <tfhe/tfhe.h>
//#include <tfhe/tfhe_io.h>
#include <ctime>
#include <random>
#include <set>
#include <fstream>
#include <cstdlib>

// Header from graph processing objects.
#include "structure/struct.h"
#include "utility/graph_client.h"
#include "structure/graph.h"
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
//	size_t poly_modulus_degree = 8192;
	size_t poly_modulus_degree = 32768;
//	cout <<CoeffModulus::MaxBitCount(32768) <<endl;
//	size_t poly_modulus_degree = 65536;
//
	prms.set_poly_modulus_degree(poly_modulus_degree);
//	prms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));
	prms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40}));	//level: 20

	double scale = pow(2.0, 40);
	auto context = SEALContext::Create(prms);
	KeyGenerator keygen(context);
	CKKSEncoder encoder(context);
	auto public_key = keygen.public_key();
    	auto secret_key = keygen.secret_key();
    	auto relin_keys = keygen.relin_keys();
	auto gal_keys = keygen.galois_keys();
    	Encryptor encryptor(context, public_key);
    	Evaluator evaluator(context);
    	Decryptor decryptor(context, secret_key);	//decryptor is only used for check result.
	size_t slot_count = encoder.slot_count();
	end_ = clock();
	cout <<"SEAL setting time(s): " <<(double)(end_ - start_) / CLOCKS_PER_SEC <<endl;

				//////////////////////
				// GSM Construction //
				//////////////////////
//	vector<string> OSList =  loadOSlist("table/OSlist");
//	queryDataByFile(argv[2], OSList, encoder, encryptor);

	//client-side
	start_ = clock();
	struct Graph G;
       	MakeGraph(G, argv[1], argv[2], argv[3], public_key, context);
	end_ = clock();
	cout <<"Time for creating PPGSM: " <<(double)(end_ - start_)/CLOCKS_PER_SEC <<endl;

	//server-side
//	createTopology(G, &key->cloud);					
//	delete_graph(G);


		//////////////////////////////////////////////////
		////////	Security Assessment	//////////
		//////////////////////////////////////////////////
	string command = argv[4];
	int startPoint, endPoint;
	bool validPoint = false;
	while(!validPoint){
		cout <<"Enter start point and end point: ";
		cin >> startPoint >>endPoint;

		if(endPoint < G.node->size() && startPoint < G.node->size()){
			validPoint = true;
		}
		else{
			cout << "Invalid Point. Try again." << endl;
		}
	}
	cout <<"Size of the graph: " << G.node->size() << endl;
	cout <<"Start point: " <<startPoint <<", ";
	cout <<"End point: " <<endPoint <<endl;		
		// Independent probability of attack success //
	if(command.compare("ind_poas") == 0){
		start_ = clock();	
		PrAtkSuccess(G,startPoint,endPoint,evaluator,relin_keys,public_key,context,secret_key);
		end_ = clock();
		cout <<"Independent attack success probabiltiy calculation time: " <<((double)(end_ - start_) / CLOCKS_PER_SEC) <<endl;
	}
		// Return on Investment (ROSI) //
	if(command.compare("rosi") == 0){
		int ROItarget;
		cout <<"Enter target node for compute ROSI: ";
		cin >>ROItarget;
		
		start_ = clock();	
		returnInvestment(G, startPoint, endPoint, ROItarget, evaluator, relin_keys, public_key, context, secret_key);
		end_ = clock();
		cout <<"ROSI calculation time: " <<((double)(end_ - start_) / CLOCKS_PER_SEC) <<endl;
	}

		// Risk & attack cost (probe) //
	if(command.compare("risk") == 0){
		start_ = clock();	
		probe(G, startPoint, endPoint, evaluator, relin_keys, public_key, context, secret_key);
		end_ = clock();
		cout <<"Attack cost & risk calculation time: " <<((double)(end_ - start_) / CLOCKS_PER_SEC) <<endl;
	}
			// Cumulative attack success //
	if(command.compare("cum_poas") == 0){
		start_ = clock();	
		cumulPrAtkSuccess(G, startPoint, evaluator, relin_keys, public_key, context, secret_key);
		end_ = clock();
		cout <<"Cumulative attack cost calculation time: " << ((double)(end_ - start_) / CLOCKS_PER_SEC) <<endl;
	}
	
			// Shortest path length (SPL) //
 	if(command.compare("spl") == 0){
		start_ = clock();	
		int shortestLen = minLength(G, startPoint, endPoint);
	 	end_ = clock();
		cout <<"SPL calculation time: " <<((double)(end_ - start_) / CLOCKS_PER_SEC) <<endl;
	}
			// Mean path length (MPL) //
	if(command.compare("mpl") == 0){
		start_ = clock();	
		double meanLen = mpl(G, startPoint, endPoint);
		end_ = clock();
		cout <<"MPL calculation time: " <<((double)(end_ - start_) / CLOCKS_PER_SEC) <<endl;
	}

	delete_graph(G);
	return 0;
}

