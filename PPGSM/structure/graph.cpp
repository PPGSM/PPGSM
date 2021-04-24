#include "struct.h"
#include "../function.h"
#include "../utility/graph_client.h"

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
#include <complex>

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
//			delete_gate_bootstrapping_ciphertext(Ne.T);
		}
//		delete_gate_bootstrapping_ciphertext(Nn->T);

		delete(Nn->Neighbors);
		delete(Nn);
	}
}

	////////////	functions used in evaluating a graph	////////////////

//function to calculate attack cost, risk
void probe(struct Graph& G, int startNumber, int destNumber, Evaluator &eval, seal::RelinKeys& relin_keys, seal::PublicKey public_key, std::shared_ptr<seal::SEALContext> context, seal::SecretKey secret_key){
	int graphSize = G.node->size();
	double scale = pow(2.0,40);
	CKKSEncoder encoder(context);

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
		// Get exist paths as plaintext
		else{
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
			for (auto p : result_paths){
				clock_t start_ = clock();
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
				for(auto e : p){
					struct nodeList N = findNode(G,e);
					if(N.node->user == false){
	                			//calculate risk
	                			eval.multiply(N.node->Impact,N.node->Pr,Rst);
	                			//eval.relinearize_inplace(Rst,relin_keys);
	                			//eval.rescale_to_next_inplace(Rst);
	                			Rst.scale() = pow(2.0, 40);
	//					parms_id_type last_parms_id = Rst.parms_id();
	//     	        			eval.mod_switch_to_inplace(risk, last_parms_id);
	                			eval.add_inplace(risk,Rst);
	
						//calculate cost
						eval.add_inplace(cost,N.node->Weight);
	        			}
				}
				eval.relinearize_inplace(risk, relin_keys);
				eval.rescale_to_next_inplace(risk);
				risk.scale() = pow(2.0, 40);
				clock_t end_ = clock();
				cout <<"calculation time for one path: " <<(double) (end_ - start_) / CLOCKS_PER_SEC <<endl;
			}
			break;
		}
	}	
}

//initial function to start minCut
int minLength(struct Graph& G, int startNumber, int destNumber){
	int MinLength = 1000000;                //just a large value.
	int graphize = G.node->size();

	for(auto inode: *(G.node)){
		inode.visited = false;
	}

	list<struct nodeList>::iterator iter;
	for(iter = G.node->begin(); iter!=G.node->end(); ++iter){
		if((*iter).node->NodeNumber == startNumber){
			(*iter).visited = true;
		}
	}

	for(auto inode : *(G.node)){	
		if(inode.node->NodeNumber != startNumber)
			continue;
		// Get exist paths as plaintext
		else{
			vector<vector<int>> result_paths;
			vector<vector<int>> Paths;
			vector<int> S;
			S.push_back(startNumber);
			Paths.push_back(S);
			while(S.size()>0){
				int c = S[S.size()-1];
				vector<int> p = Paths[Paths.size()-1];
				S.pop_back();
				Paths.pop_back();
				if(p.size() > MinLength)
					continue;
				else{
					struct nodeList n__ = findNode(G,c);
					for(auto e : *(n__.node->Neighbors)){
						bool searched = false;
						for(auto x : p){
							if(e.NodeNumber == x)	searched = true;
						}
						if(searched)	continue;
						
						if(e.NodeNumber == destNumber){
							p.push_back(e.NodeNumber);
							result_paths.push_back(p);
							if(p.size() < MinLength){
								MinLength = p.size();
							}
						}
						else{
							p.push_back(e.NodeNumber);
							Paths.push_back(p);
							S.push_back(e.NodeNumber);
						}
					}
				}
			}
			break;
		}
	}
	return MinLength;
}

//initial function to start mpl
double mpl(struct Graph& G, int startNumber, int destNumber){	
	int graphize = G.node->size();
	int routeNumber = 0;
	int totalHop = 0;

	for(auto inode: *(G.node)){
		inode.visited = false;
	}

	list<struct nodeList>::iterator iter;
	for(iter = G.node->begin(); iter!=G.node->end(); ++iter){
		if((*iter).node->NodeNumber == startNumber){
			(*iter).visited = true;
		}
	}

	for(auto inode : *(G.node)){	
		if(inode.node->NodeNumber != startNumber)
			continue;
		// Get exist paths as plaintext
		else{
			vector<vector<int>> result_paths;
			vector<vector<int>> Paths;
			vector<int> S;
			S.push_back(startNumber);
			Paths.push_back(S);
			while(S.size()>0){
				int c = S[S.size()-1];
				vector<int> p = Paths[Paths.size()-1];
				S.pop_back();
				Paths.pop_back();
				struct nodeList n__ = findNode(G,c);
				for(auto e : *(n__.node->Neighbors)){
					bool searched = false;
					for(auto x : p){
						if(e.NodeNumber == x)	searched = true;
					}
					if(searched)	continue;
					
					if(e.NodeNumber == destNumber){
						p.push_back(e.NodeNumber);
						result_paths.push_back(p);
					}
					else{
						p.push_back(e.NodeNumber);
						Paths.push_back(p);
						S.push_back(e.NodeNumber);
					}
				}
			}
			routeNumber = result_paths.size();		
			for(auto p : result_paths){
				totalHop += p.size();
			}	
		}
		break;
	}
	double result = (double)totalHop / (double)routeNumber;
	return result;
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

void PrAtkSuccess(struct Graph& G, int startNumber, int destNumber, Evaluator &eval, seal::RelinKeys& relin_keys, seal::PublicKey public_key, std::shared_ptr<seal::SEALContext> context, seal::SecretKey secret_key){
	double scale = pow(2.0,40);
	CKKSEncoder encoder(context);
	Encryptor encryptor(context, public_key);
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
		vector<int> P;
		vector<Ciphertext> pathPr;
		vector<Ciphertext> realPath;
		vector<int> path;
                // Temp - start
                vector<vector<int>> result_paths;
		vector<vector<int>> Paths;
                vector<int> S;
                S.push_back(startNumber);
                Paths.push_back(S);
		int tryNum = 0;
                while(S.size()>0){
			if(tryNum > 500000000){
				cout <<"There are too many tries" <<endl;
				tryNum = 0;
				return;
			}
                        int c = S[S.size()-1];
                        vector<int> p = Paths[Paths.size()-1];
                        S.pop_back();
                        Paths.pop_back();
                        struct nodeList n__ = findNode(G,c);
                        for(auto e : *(n__.node->Neighbors)){
                                bool searched = false;
                                for(auto x : p){
                                        if(e.NodeNumber == x)   searched = true;
                                }
                                if(searched)    continue;
                                if(e.NodeNumber == destNumber){
                                        p.push_back(e.NodeNumber);
                                        result_paths.push_back(p);
					tryNum ++;
                                }
                                else{
                                        // path update
                                        p.push_back(e.NodeNumber);

                                        // put into the stack.
                                        Paths.push_back(p);
                                        S.push_back(e.NodeNumber);
					tryNum ++;
                                }
                        }
                }
		cout <<"Path num: " <<result_paths.size() <<endl;
		// Calculate ciphertext part
		for (auto p : result_paths){
//			cout <<"path length: " <<p.size() <<endl;
//			cout <<"path: "; 
			Plaintext plainRealPath;	
			encoder.encode(0, scale, plainRealPath);
			Ciphertext realpath;
			encryptor.encrypt(plainRealPath, realpath);
		
			Plaintext path_lg_pr;
		        encoder.encode(0, scale, path_lg_pr);
		        Ciphertext Path_lgpr;
		        encryptor.encrypt(path_lg_pr,Path_lgpr);

                        for(auto e : p)
                        {
//				cout <<e <<"-->";
                                struct nodeList N = findNode(G,e);
                                if(N.node->user == false){
					//calculate realPath
					eval.add_inplace(realpath, N.node->T);
                                        //calculate log_pr
					eval.add_inplace(Path_lgpr,N.node->logPr);
                                }
                        }
//			cout <<endl;
			realPath.push_back(realpath);
			/*
			//test
			Decryptor decryptor(context, secret_key);
			Plaintext dummy_result;
	                decryptor.decrypt(realpath, dummy_result);
        	        vector<double> dummyResult;
                	encoder.decode(dummy_result, dummyResult);
	                cout << "test for dummy path: " <<dummyResult[0] <<endl;
			*/
			pathPr.push_back(Path_lgpr);
                }
		
		int size = pathPr.size();
		
		Plaintext ResultPr;
		encoder.encode(0,scale,ResultPr);
		Ciphertext finalResult;
		encryptor.encrypt(ResultPr, finalResult);
		Decryptor decryptor(context, secret_key);

		for(int i=0;i<size;i++){
			//modify realpath -> real:1 , else:0
			////approximate 2*cos(n*pi/128)
			Plaintext cos_eff_plain1, cos_eff_plain2, cos_eff_plain3, cos_eff_plain4;
			encoder.encode(2, scale, cos_eff_plain1);
			encoder.encode(-1, scale, cos_eff_plain2);
			encoder.encode(0.083333, scale, cos_eff_plain3);
			encoder.encode(-0.0027777, scale, cos_eff_plain4);

			Ciphertext cos_eff1, cos_eff2, cos_eff3, cos_eff4, cos_x2, cos_x4, cos_x6, cos_x6_temp;
			encryptor.encrypt(cos_eff_plain1, cos_eff1);
			encryptor.encrypt(cos_eff_plain2, cos_eff2);
			encryptor.encrypt(cos_eff_plain3, cos_eff3);
			encryptor.encrypt(cos_eff_plain4, cos_eff4);
			
			eval.square(realPath[i], cos_x2);
			eval.relinearize_inplace(cos_x2, relin_keys);
			eval.rescale_to_next_inplace(cos_x2);			//get x^2
			
			parms_id_type last_parms_id = cos_x2.parms_id();
			eval.mod_switch_to_inplace(cos_eff4, last_parms_id);
			eval.multiply(cos_x2, cos_eff4, cos_x6_temp);
			eval.relinearize_inplace(cos_x6_temp, relin_keys);
			eval.rescale_to_next_inplace(cos_x6_temp);		//get -x^2/720
			eval.square(cos_x2, cos_x4);
			eval.relinearize_inplace(cos_x4, relin_keys);
			eval.rescale_to_next_inplace(cos_x4);			//get x^4
			eval.multiply(cos_x6_temp, cos_x4, cos_x6);
			eval.relinearize_inplace(cos_x6, relin_keys);
			eval.rescale_to_next_inplace(cos_x6);			//get -x^6/720

			last_parms_id = cos_x4.parms_id();
			eval.mod_switch_to_inplace(cos_eff3, last_parms_id);
			eval.multiply_inplace(cos_x4, cos_eff3);
			eval.relinearize_inplace(cos_x4, relin_keys);
			eval.rescale_to_next_inplace(cos_x4);			//get x^4/24
			
			last_parms_id = cos_x2.parms_id();
			eval.mod_switch_to_inplace(cos_eff2, last_parms_id);
			eval.multiply_inplace(cos_x2, cos_eff2);
			eval.relinearize_inplace(cos_x2, relin_keys);
			eval.rescale_to_next_inplace(cos_x2);			//get -x^2/2
	
			last_parms_id = cos_x6.parms_id();
			eval.mod_switch_to_inplace(cos_x2, last_parms_id);
			eval.mod_switch_to_inplace(cos_eff1, last_parms_id);

			Ciphertext isReal_temp;
			cos_x2.scale() = pow(2.0, 40);
			cos_x4.scale() = pow(2.0, 40);
			cos_x6.scale() = pow(2.0, 40);
			eval.add(cos_eff1, cos_x2, isReal_temp);
			eval.add_inplace(isReal_temp, cos_x4);
			eval.add_inplace(isReal_temp, cos_x6);			//level:17

			////calculate isReal
			Plaintext minusOne_plain, minusTwo_plain, half_plain, sinfun;
			encoder.encode(-1, scale, minusOne_plain);
			encoder.encode(-2, scale, minusTwo_plain);
			encoder.encode(0.5, scale, half_plain);
			encoder.encode(1, scale, sinfun);
			Ciphertext minusOne, minusTwo, half, sinFun, cosFun, one;
			encryptor.encrypt(minusOne_plain, minusOne);
			encryptor.encrypt(minusTwo_plain, minusTwo);
			encryptor.encrypt(half_plain, half);
			encryptor.encrypt(sinfun, one);
			encryptor.encrypt(sinfun, sinFun);
			cosFun = isReal_temp;
			last_parms_id = cosFun.parms_id();
			eval.mod_switch_to_inplace(sinFun, last_parms_id);
			
			for(int j=0;j<6;j++){
				Ciphertext sin_temp, cos_temp;
				sin_temp = sinFun;
				cos_temp = cosFun;
				eval.square(cos_temp, cosFun);
				eval.relinearize_inplace(cosFun, relin_keys);
				eval.rescale_to_next_inplace(cosFun);			//get tmp^2
				cosFun.scale() = pow(2.0,40);
				last_parms_id = cosFun.parms_id();
				eval.mod_switch_to_inplace(minusTwo, last_parms_id);
				eval.add_inplace(cosFun, minusTwo);			//update cosFun
				
				last_parms_id = cos_temp.parms_id();
				eval.mod_switch_to_inplace(half, last_parms_id);
				eval.multiply_inplace(cos_temp, half);
				eval.relinearize_inplace(cos_temp, relin_keys);
				eval.rescale_to_next_inplace(cos_temp);			//get tmp/2		
				last_parms_id = cos_temp.parms_id();
				eval.mod_switch_to_inplace(sin_temp, last_parms_id);
				eval.multiply(sin_temp, cos_temp, sinFun);
				eval.relinearize_inplace(sinFun, relin_keys);
				eval.rescale_to_next_inplace(sinFun);			//update sinFun
				sinFun.scale() = pow(2.0,40);
			}
			Ciphertext isReal = sinFun;	

			/*
			//test
			Plaintext plain_result;
	                decryptor.decrypt(isReal, plain_result);
        	        vector<double> result;
                	encoder.decode(plain_result, result);
	                cout << "test for isReal: " <<result[0] <<endl;
			*/

			//preprocessing of pathPr using isReal
			Plaintext zero_plain, root_plain;
			encoder.encode(3.55388+0.789422i, scale, root_plain);
			Ciphertext pathProb, pathPr_temp, isDummy, root;
			pathPr_temp = pathPr[i];
			encryptor.encrypt(root_plain, root);
			last_parms_id = isReal.parms_id();
			eval.mod_switch_to_inplace(one, last_parms_id);
			eval.mod_switch_to_inplace(pathPr_temp, last_parms_id);
			eval.multiply(isReal, pathPr_temp, pathProb);
			eval.relinearize_inplace(pathProb, relin_keys);
			eval.rescale_to_next_inplace(pathProb);			//update pathProb
			pathProb.scale() = pow(2.0,40);

			eval.mod_switch_to_inplace(minusOne, last_parms_id);
			eval.add(minusOne, isReal, isDummy);
			last_parms_id = isDummy.parms_id();
			eval.mod_switch_to_inplace(root, last_parms_id);
			eval.multiply_inplace(isDummy, root);
			eval.relinearize_inplace(isDummy, relin_keys);
			eval.rescale_to_next_inplace(isDummy);			//update isDummy
			isDummy.scale() = pow(2.0,40);
			last_parms_id = pathProb.parms_id();
			eval.mod_switch_to_inplace(isDummy, last_parms_id);
			eval.add_inplace(pathProb, isDummy);

			//approximate first Taylor expansion
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
	
			//1st term
			last_parms_id = pathProb.parms_id();
			eval.mod_switch_to_inplace(temp1, last_parms_id);
			eval.multiply_inplace(temp1, pathProb);
			eval.relinearize_inplace(temp1, relin_keys);
			eval.rescale_to_next_inplace(temp1);
			temp1.scale() = pow(2.0,40);

			//2nd term
			eval.square(pathProb, temp);
			eval.relinearize_inplace(temp, relin_keys);
			eval.rescale_to_next_inplace(temp);
			
			last_parms_id = temp.parms_id();
			temp.scale() = pow(2.0,40);
			eval.mod_switch_to_inplace(temp2, last_parms_id);
			eval.multiply_inplace(temp2, temp);
			eval.relinearize_inplace(temp2, relin_keys);
			eval.rescale_to_next_inplace(temp2);
			temp2.scale() = pow(2.0,40);

			//3rd term
			last_parms_id = pathProb.parms_id();
			eval.mod_switch_to_inplace(temp3, last_parms_id);
			eval.multiply_inplace(temp3, pathProb);
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
			last_parms_id = pathProb.parms_id();
			eval.mod_switch_to_inplace(temp5, last_parms_id);
			eval.multiply_inplace(temp5, pathProb);
			eval.relinearize_inplace(temp5, relin_keys);
                        eval.rescale_to_next_inplace(temp5);
                        temp5.scale() = pow(2.0,40);
			
			last_parms_id = temp_a.parms_id();
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
                        eval.multiply_inplace(temp6, temp_a);
                        eval.relinearize_inplace(temp6, relin_keys);
                        eval.rescale_to_next_inplace(temp6);
                        temp6.scale() = pow(2.0,40);

			//7th term
			last_parms_id = pathProb.parms_id();
			eval.mod_switch_to_inplace(temp7, last_parms_id);
			eval.multiply_inplace(temp7, pathProb);
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

                        last_parms_id = temp7.parms_id();
                        eval.mod_switch_to_inplace(temp_a, last_parms_id);
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
			last_parms_id = pathProb.parms_id();
			eval.mod_switch_to_inplace(temp9, last_parms_id);
			eval.multiply_inplace(temp9, pathProb);
                        eval.relinearize_inplace(temp9, relin_keys);
                        eval.rescale_to_next_inplace(temp9);
                        temp9.scale() = pow(2.0,40);

                        last_parms_id = temp_b.parms_id();
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

			//add all terms
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
			temp0.scale() = pow(2.0, 40);
			/*
			//test
			Plaintext plain_result2;
	                decryptor.decrypt(temp0, plain_result2);
	       	        vector<double> result2;
                	encoder.decode(plain_result2, result2);
	                cout << "pr: " <<result2[0] <<endl;
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

			last_parms_id = temp0.parms_id();
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
			eval.rescale_to_next_inplace(secondtemp9);
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
	
			//KEEP MODIFY
			//mult x^8
			eval.square(secondtemp_a, secondtemp_b);
                        eval.relinearize_inplace(secondtemp_b, relin_keys);
                        eval.rescale_to_next_inplace(secondtemp_b);
                        secondtemp_b.scale() = pow(2.0, 40);
                        last_parms_id = secondtemp_b.parms_id();
                        eval.mod_switch_to_inplace(secondtemp8, last_parms_id);
                        eval.mod_switch_to_inplace(secondtemp9, last_parms_id);
                        eval.mod_switch_to_inplace(secondtemp10, last_parms_id);
                        secondtemp8.scale() = pow(2.0,40);
                        secondtemp9.scale() = pow(2.0,40);
                        secondtemp10.scale() = pow(2.0,40);
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
                        Plaintext plain_result3;
                        decryptor.decrypt(secondtemp1, plain_result3);
                        vector<double> result3;
                        encoder.decode(plain_result3, result3);
                        cout << "log(1-pr): " <<result3[0] <<endl;
			*/
			last_parms_id = secondtemp1.parms_id();
			eval.mod_switch_to_inplace(finalResult, last_parms_id);
			eval.add_inplace(finalResult, secondtemp1);
		}
			/*
			//test
                        Plaintext plain_result4;
                        decryptor.decrypt(finalResult, plain_result4);
                        vector<double> result4;
                        encoder.decode(plain_result4, result4);
                        cout << "result: " <<result4[0] <<endl;
			*/
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

//function to calculate return on investment
void returnInvestment(struct Graph& G, int startNumber, int destNumber, int target, Evaluator &eval, seal::RelinKeys& relin_keys, seal::PublicKey public_key, std::shared_ptr<seal::SEALContext> context, seal::SecretKey secret_key){
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
		else{
			vector<int> path;
			// Temp - start
			vector<vector<int>> Patched_paths;
			vector<vector<int>> Paths;
			vector<int> S;
			S.push_back(startNumber);
			Paths.push_back(S);
			while(S.size()>0){
				int c = S[S.size()-1];
				vector<int> p = Paths[Paths.size()-1];
				S.pop_back();
				Paths.pop_back();
				struct nodeList n__ = findNode(G,c);
				for(auto e : *(n__.node->Neighbors)){
					bool searched = false;
					for(auto x : p){
						if(e.NodeNumber == x)	searched = true;
					}
					if(searched)	continue;
					if(e.NodeNumber == destNumber){
						p.push_back(e.NodeNumber);
						bool patched = false;
						for(auto x : p)
							if(x == target)	patched = true;
						if(!patched)	continue;
						Patched_paths.push_back(p);
					}
					else{
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
			for (auto p : Patched_paths){
				for(auto e : p){
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

//               			eval.relinearize_inplace(risk,relin_keys);
//             			eval.rescale_to_next_inplace(risk);
//				risk.scale() = pow(2.0, 40);
				//cout << endl;
			}
			struct nodeList targetNode = findNode(G,target);
			parms_id_type last_parms_id = risk.parms_id();
			risk.scale() = pow(2.0,40);
			eval.mod_switch_to_inplace(targetNode.node->Patch, last_parms_id);
			eval.mod_switch_to_inplace(targetNode.node->inversePatch, last_parms_id);
			eval.sub_inplace(risk, targetNode.node->Patch);
			eval.multiply_inplace(risk, targetNode.node->inversePatch);		
		}
		break;
	}
}
