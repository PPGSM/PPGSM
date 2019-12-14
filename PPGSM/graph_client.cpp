#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>

#include <iostream>
#include <stdlib.h>
#include <vector>
#include <list>

#include "struct.h"
#include "function.h"
#include "encryption.h"

#define	NODE_ID 8

using namespace seal;
///////////////		adding components of the graph(node & edge)	//////////////

//create a real node
void createNode(struct Graph &G, int nodeNumber, double weight, double impact, double pr, double logPr, double patch, double inv_patch, bool isUser, bool isTrue, const TFheGateBootstrappingSecretKeySet* PK, seal::PublicKey public_key, std::shared_ptr<seal::SEALContext> context)
{
	//Deprecated
	/*
	Ctxt w(publicKey);
	Ctxt i(publicKey);
	Ctxt p(publicKey);
	*/

	struct nodeList P;
	P.unchangeable    = false;
	P.visited	  = false;
	struct node *Pn   = new struct node;
	Pn->user	  = isUser;
	Pn->NodeNumber    = nodeNumber;
	Pn->Neighbors     = new std::list<struct Neighbor>;
	Pn->T		  = new_gate_bootstrapping_ciphertext(PK->cloud.params);

	double scale = pow(2.0, 40);

	CKKSEncoder encoder(context);

	Plaintext Wplain,Iplain,Pplain,Prplain,Patchplain,InvPatchplain;
	encoder.encode(weight, scale, Wplain);
	encoder.encode(impact, scale, Iplain);
	encoder.encode(pr, scale, Pplain);
	encoder.encode(logPr, scale, Prplain);
	encoder.encode(patch, scale, Patchplain);
	encoder.encode(inv_patch, scale, InvPatchplain);

	Encryptor encryptor(context,public_key);
	encryptor.encrypt(Wplain,Pn->Weight);
	encryptor.encrypt(Iplain,Pn->Impact);
	encryptor.encrypt(Pplain,Pn->Pr);
	encryptor.encrypt(Prplain,Pn->logPr);
	encryptor.encrypt(Patchplain,Pn->Patch);
	encryptor.encrypt(InvPatchplain,Pn->inversePatch);

	bootsCONSTANT(Pn->T, (int)isTrue, &(PK->cloud));
	
	P.node = Pn;

	G.node->push_back(P);

        return;
}


//create a duumy node
void createDummyNode(struct Graph &G, int weight, int impact, double pr, double logPr, double patch, double inv_patch, const TFheGateBootstrappingSecretKeySet *PK, seal::PublicKey public_key, std::shared_ptr<seal::SEALContext> context)
{
        createNode(G, G.node->size(), weight, impact, pr, logPr, patch, inv_patch, false, false, PK,public_key,context);
}


//create a real edge
void createEdge(struct node* N, int target, bool isTrue, const TFheGateBootstrappingCloudKeySet* EK)
{
	struct Neighbor P;
	P.NodeNumber = target;
	P.T = new_gate_bootstrapping_ciphertext(EK->params);
	bootsCONSTANT(P.T, isTrue, EK);
	N->Neighbors->push_back(P);

        return;
}


//create a dummy edge
void createDummyEdge(struct Graph &G, int src, int target, bool isTrue, const TFheGateBootstrappingCloudKeySet* EK)
{
	std::list<struct nodeList>::iterator iter;
	for(iter = G.node->begin(); (*iter).node->NodeNumber != src; ++iter);

	createEdge((*iter).node, target, isTrue, EK);
}
// Deprecated : we need to handle whole part of HElib
/*
//it helps to input the information of nodes
void getGraphInfo(const TFheGateBootstrappingSecretKeySet* PK, const FHEPubKey& publicKey, const FHESecKey& secKey)
{
	std::fstream fp("PathInfo", std::fstream::in);
	std::fstream dfp("DPathInfo", std::fstream::in);
	std::fstream ifp("NodeInfo", std::fstream::in);
	while(true)
	{
		int L, N;
		char B;
		
		// Load path length information
		fp >> L;
		if(fp.fail())
		{
			fp.close();
			dfp.close();
			ifp.close();
			return;
		}	
	
		// Load path information
		std::vector<int> Path;
		for(int i = 0; i < L; i++)
		{
			fp >> N;
			Path.push_back(N);		
		}
		std::cout << Path;
	
		const TFheGateBootstrappingCloudKeySet* EK = &PK->cloud;
	
		// Load dummy path information.
		LweSample* X = new_gate_bootstrapping_ciphertext(EK->params);	
		import_gate_bootstrapping_ciphertext_fromStream(dfp, X, EK->params);
		std::cout << " | true path : " << bootsSymDecrypt(X,PK);
	
		// Load Node information
		Ctxt cost(publicKey);
		Ctxt risk(publicKey);
	
		ifp >> cost;
		ifp >> risk;
	
		printf(", cost : ");
		NTL::ZZX decCost;
		secKey.Decrypt(decCost,cost);
		std::cout << decCost[0];
		printf(", risk : ");
		NTL::ZZX decRisk;
		secKey.Decrypt(decRisk,risk);
		std::cout << decRisk[0] << std::endl;
	}
}
*/
