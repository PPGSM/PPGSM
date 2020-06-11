#include <vector>
#include <set>
using namespace std;
void delete_graph(struct Graph& G);
void probe(struct Graph& G, Ciphertext cost, Ciphertext risk, struct nodeList &N, LweSample* Tmp, vector<int> path, int dest, const TFheGateBootstrappingCloudKeySet* EK, const TFheGateBootstrappingSecretKeySet *PK, Evaluator &eval, auto &relin_keys, std::shared_ptr<seal::SEALContext> context, auto &secret_key);
void init_probe(struct Graph& G, int startNumber, int destNumber, const TFheGateBootstrappingCloudKeySet* EK, const TFheGateBootstrappingSecretKeySet *PK, Evaluator &eval, seal::RelinKeys& relin_keys, seal::PublicKey public_key, std::shared_ptr<seal::SEALContext> context, seal::SecretKey secret_key);
void probeMinCut(struct Graph& G, struct nodeList& N, vector<int> path, int dest, int &tryCnt, const TFheGateBootstrappingCloudKeySet* EK);
int minCut(struct Graph& G, int startNumber, int destNumber, const TFheGateBootstrappingCloudKeySet* EK);
void probeMinLength(struct Graph& G, struct nodeList& N, vector<int> path, int* Length, int dest, const TFheGateBootstrappingCloudKeySet* EK);
int minLength(struct Graph& G, int startNumber, int destNumber, const TFheGateBootstrappingCloudKeySet* EK);
void probeShortestPath(struct Graph& G, Ciphertext cost, Ciphertext risk, struct nodeList &N, LweSample* Tmp, vector<int> path, int dest, int shortestLength, double mpl, const TFheGateBootstrappingCloudKeySet* EK, Evaluator &eval, auto &relin_keys, std::shared_ptr<seal::SEALContext> context);
void init_probeShortestPath(struct Graph& G, int startNumber, int destNumber, int shortestLength, double mpl, const TFheGateBootstrappingCloudKeySet* EK, Evaluator &eval, seal::RelinKeys& relin_keys, seal::PublicKey public_key, std::shared_ptr<seal::SEALContext> context);
void probeMpl(struct Graph& G, struct nodeList& N, vector<int> path, int* routeNumber, int* totalHop, int dest, const TFheGateBootstrappingCloudKeySet* EK);
void mpl(struct Graph& G, int startNumber, int destNumber, const TFheGateBootstrappingCloudKeySet* EK, Evaluator &eval, seal::RelinKeys& relin_keys, seal::PublicKey public_key, std::shared_ptr<seal::SEALContext> context);
struct degree getDegree(struct Graph& G);
struct nodeList findNode(struct Graph &G, int nodeNumber);
std::vector<int> totalDegree(struct degree &D);
void addNodeRestriction(Graph *G, int nodeNumber);
void addEdgeRestriction(Graph *G, int from, int to);
void prune(struct Graph &G, struct degree &V, int number);
void PrAtkSuccess(struct Graph& G, int startNumber, int destNumber, const TFheGateBootstrappingCloudKeySet* EK, const TFheGateBootstrappingSecretKeySet *PK, Evaluator &eval, seal::RelinKeys& relin_keys, seal::PublicKey public_key, std::shared_ptr<seal::SEALContext> context, seal::SecretKey secret_key);
void cumulPrAtkSuccess(struct Graph& G, int startNumber, Evaluator &eval, seal::RelinKeys& relin_keys, seal::PublicKey public_key, std::shared_ptr<seal::SEALContext> context, seal::SecretKey secret_key);
void returnInvestment(struct Graph& G, int startNumber, int destNumber, int target, const TFheGateBootstrappingCloudKeySet* EK, const TFheGateBootstrappingSecretKeySet *PK, Evaluator &eval, seal::RelinKeys& relin_keys, seal::PublicKey public_key, std::shared_ptr<seal::SEALContext> context, seal::SecretKey secret_key);
void processQuery(Graph &G, int NID, std::shared_ptr<seal::SEALContext> context, GaloisKeys &gal_keys, Evaluator &evaluator, seal::RelinKeys &relin_keys);
void GSMCreation(Graph &G, std::shared_ptr<seal::SEALContext> context, GaloisKeys &gal_keys, Evaluator &evaluator, seal::RelinKeys &relin_keys, const TFheGateBootstrappingCloudKeySet *EK);

