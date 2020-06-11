#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>

#include <iostream>
#include <fstream>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <vector>
#include <list>

#include "../structure/struct.h"

#define	NODE_ID 8

using namespace seal;
using namespace std;
///////////////		adding components of the graph(node & edge)	//////////////

//create a real node
void createNode(struct Graph &G, int nodeNumber, double weight, double impact, double pr, double logPr, double patch, double inv_patch, bool isUser, bool isTrue, const TFheGateBootstrappingSecretKeySet* PK, seal::PublicKey public_key, std::shared_ptr<seal::SEALContext> context){
	struct nodeList P;
	P.unchangeable    = false;
	P.visited	  = false;
	struct node *Pn   = new struct node;
	Pn->user	  = isUser;
	Pn->NodeNumber    = nodeNumber;
	Pn->Neighbors     = new std::list<struct Neighbor>;
	Pn->T		  = new_gate_bootstrapping_ciphertext(PK->cloud.params);

	Pn->exactPr	  = pr;
	Pn->exactlogPr	  = logPr;

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

	Pn->exactPr = pr;
	Pn->exactlogPr = logPr;
/*
	std::ofstream sizeout("nodeSize.txt", std::ios::app);
	(Pn->Weight).save(sizeout);
	(Pn->Impact).save(sizeout);
	(Pn->Pr).save(sizeout);
	(Pn->logPr).save(sizeout);
	(Pn->Patch).save(sizeout);
	(Pn->inversePatch).save(sizeout);
	sizeout.close();
*/

//	cout <<"setting: " <<context->get_context_data((Pn->Pr).parms_id())->chain_index() <<endl;


	bootsCONSTANT(Pn->T, (int)isTrue, &(PK->cloud));
	P.node = Pn;
	G.node->push_back(P);
        return;
}


//create a duumy node
void createDummyNode(struct Graph &G, int weight, int impact, double pr, double logPr, double patch, double inv_patch, const TFheGateBootstrappingSecretKeySet *PK, seal::PublicKey public_key, std::shared_ptr<seal::SEALContext> context){
        createNode(G, G.node->size(), weight, impact, pr, logPr, patch, inv_patch, false, false, PK,public_key,context);
}

//create a real edge
void createEdge(struct node* N, int target, bool isTrue, const TFheGateBootstrappingCloudKeySet* EK){
	struct Neighbor P;
	P.NodeNumber = target;
	P.T = new_gate_bootstrapping_ciphertext(EK->params);
	bootsCONSTANT(P.T, isTrue, EK);
	N->Neighbors->push_back(P);
        return;
}

//create a dummy edge
void createDummyEdge(struct Graph &G, int src, int target, bool isTrue, const TFheGateBootstrappingCloudKeySet* EK){
	std::list<struct nodeList>::iterator iter;
	for(iter = G.node->begin(); (*iter).node->NodeNumber != src; ++iter);

	createEdge((*iter).node, target, isTrue, EK);
}

//Make a initial graph(not modified) by using adjacent matrix.
void MakeGraph(Graph& G, char *Mat, char *NodeInfo, char *Trait, const TFheGateBootstrappingSecretKeySet *PK, seal::PublicKey public_key, std::shared_ptr<seal::SEALContext> context){
	G.node = new std::list<struct nodeList>;
	// Matrix reading stage
	vector<vector<int>> V; 
	char T;
	int mat = open(Mat, O_RDONLY);		//read adjacent matrix
	int nod = open(NodeInfo, O_RDONLY);	//read file about type of each node
	int tra = open(Trait, O_RDONLY);	//read file about information of node types.
	if(mat < 0){
		printf("There was a problem reading matrix information file. exit\n");
		exit(0);	
	}
	
	int c = read(mat, &T, 1);
	while(c > 0){
		vector<int> t;
		while(T != '\n' && c > 0){
			if('0' <= T && T <= '2'){ // If program read number 0 or 1, record it.{
				t.push_back(T-'0');
			}
			c = read(mat, &T, 1);
		}
		V.push_back(t); // store the neighbor information to adjacant node vector.
		c = read(mat, &T, 1);
	}

	vector<struct TraitInfo> Tr;
	if(tra < 0){
		printf("There was a problem reading trait information file. exit\n");
		exit(0);
	}

	c = read(tra, &T, 1);
	while(c > 0){
		struct TraitInfo X;
			
		int stage = 0;
		vector<char> t; // link to type
		vector<char> c1; // link to cost
		vector<char> i1; // link to impact
		vector<char> p; // link to probability
		vector<char> patch; //link to patch
		while(T != '\n' && c > 0){
			if(T == ' '){
				stage++;
			}
			else{
				if(stage == 0){
					t.push_back(T);	
				}
				else if(stage == 1){
					c1.push_back(T);	
				}
				else if(stage == 2){
					i1.push_back(T);	
				}
				else if(stage == 3){
					p.push_back(T);	
				}
				else if(stage ==4){
					patch.push_back(T);
				}
			}
			c = read(tra, &T, 1);	
		}

		int len = t.size();
		X.type = new char[len+1];
		for(int i = 0; i < len; i++){
			X.type[i] = t[i];
		}	
		X.type[len] = '\0';

		len = c1.size();
		char c2[len+1];
		for(int i = 0; i < len; i++){
			c2[i] = c1[i];
		}
		c2[len] = '\0';
		X.cost = atoi(c2);
		
		len = i1.size();
		char i2[len+1];
		for(int i = 0; i < len; i++){
			i2[i] = i1[i];
		}
		i2[len] = '\0';
		X.impact = atoi(i2);

		len = p.size();
		char p2[len+1];
		for(int i = 0; i < len; i++){
			p2[i] = p[i];
		}
		p2[len] = '\0';
		X.pr = atof(p2);
		X.logPr = log(X.pr);

//		cout <<X.logPr <<endl;		//change

		len = patch.size();
		char patch2[len+1];
		for(int i=0;i<len;i++){
			patch2[i] = patch[i];
		}
		patch2[len] = '\0';
		X.patch = atof(patch2);
		X.inverse_patch = 1 / X.patch;
		Tr.push_back(X);

		c = read(tra, &T, 1);
	}

	c = read(nod, &T, 1);
	int nodeNumber = 0;
	while(c > 0){
		vector<char> t;
		while(T != '\n' && c > 0){
			t.push_back(T);
			c = read(nod, &T, 1);
		}
		int len = t.size();
		char* t2 = new char[len+1];
		for(int i = 0; i < len; i++){
			t2[i] = t[i];
		}		
		t2[len] = '\0';

		int TrSize = Tr.size();
		bool User = true;
		for(int i = 0; i < TrSize; i++){
			if(strncmp(t2, Tr[i].type, len) == 0){
				createNode(G, nodeNumber, Tr[i].cost, Tr[i].impact, Tr[i].pr, Tr[i].logPr, Tr[i].patch, Tr[i].inverse_patch, false, true,PK,public_key,context);
				nodeNumber++;
				User = false;
				break;
			}
		}
		if(User == true){
			createNode(G, nodeNumber, 0, 0, 0.0, -100000, 1, 1, true, true, PK,public_key,context);
			nodeNumber++;
		}
		c = read(nod, &T, 1);
	}

	list<struct nodeList>::iterator iter;
	for(iter = G.node->begin(); iter != G.node->end(); ++iter){
		int Index = (*iter).node->NodeNumber;
		int lenN  = V[Index].size();		

		for(int i = 0; i < lenN; i++){
			if(V[Index][i] == 1 && Index != i){
				createEdge((*iter).node, i, true, &PK->cloud);
			}
			else if(V[Index][i] == 2 && Index != i){
				createEdge((*iter).node, i, false, &PK->cloud);
			}
		} 
	}
}

//// functions for creating info which are required to create GSM in server ////
void queryData(std::vector<std::string> &OSlist, std::string &targetOS, int NID, CKKSEncoder &encoder, Encryptor &encryptor)
{
        int index = 0;
        int Tablesize = OSlist.size();
        for(int i = 0; i< Tablesize; i++)
        {
                if(targetOS.compare(OSlist[i]) == 0)    break;
                index++;
        }
        if(index>=Tablesize)    return;

        std::vector<double> input;
        for(int i=0; i<Tablesize; i++)
        {
                input.push_back(0);
        }
        input[index] = 1;
        double scale = pow(2.0, 40);
        Plaintext plain;
        encoder.encode(input, scale, plain);
        Ciphertext result;
        encryptor.encrypt(plain, result);
        std::ofstream ctresult("query/queryProduct"+to_string(NID),std::ofstream::binary);
        result.save(ctresult);
        std::ofstream ptresult("query/queryTarget"+to_string(NID));
        ptresult << NID;
        ctresult.close();
        ptresult.close();
}

void queryDataByFile(char* f, std::vector<std::string> &OSlist, CKKSEncoder &encoder, Encryptor &encryptor)
{
        std::string input(f);

        std::ifstream T(input);
        if(!T)
        {
                cout << "There is a problem with opening input files... exit" << endl;
                exit(0);
        }
        std::string line;
        int targetNID = 0;
        while(std::getline(T,line))
        {
                queryData(OSlist, line, targetNID, encoder, encryptor);
                targetNID++;
        }
}

void createTopology(Graph &G, const TFheGateBootstrappingCloudKeySet *EK)
{
        int node_counter = 0;
        int edge_counter = 0;
        for(auto N : *(G.node))
        {
                int NID = N.node->NodeNumber;
                //save node information
                ofstream nodeTruth("nodes/nodeTruth"+to_string(NID),std::ofstream::binary);
                export_gate_bootstrapping_ciphertext_toStream(nodeTruth,N.node->T,EK->params);
                nodeTruth.close();

                //save edge information
                struct node* Nn = N.node;
                for(auto Ne : *(Nn->Neighbors))
                {
                        ofstream edgeTruth("edges/edgeTruth"+to_string(edge_counter),std::ofstream::binary);
                        export_gate_bootstrapping_ciphertext_toStream(edgeTruth,Ne.T,EK->params);
                        ofstream edgeInfo("edges/edge"+to_string(edge_counter));
                        edgeInfo << NID << " " << Ne.NodeNumber;
                        edgeTruth.close();
                        edgeInfo.close();
                        edge_counter++;
                }
                node_counter++;
        }
        ofstream nodeNum("nodes/number_nodes");
        nodeNum << node_counter;
        ofstream edgeNum("edges/number_edges");
        edgeNum << edge_counter;
        nodeNum.close();
        edgeNum.close();

}

std::vector<std::string> loadOSlist(std::string input)
{
        vector<string> output;
        std::ifstream x(input);
        std::string line;
        while(std::getline(x,line))
        {
                output.push_back(line);
        }
        return output;
}

