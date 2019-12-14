#include <vector>
#include <set>
using namespace std;
void probe(struct Graph& G, Ciphertext cost, Ciphertext risk, struct nodeList &N, LweSample* Tmp, vector<int> path, int dest, const TFheGateBootstrappingCloudKeySet* EK, const TFheGateBootstrappingSecretKeySet *PK, Evaluator &eval, auto &relin_keys, std::shared_ptr<seal::SEALContext> context, auto &secret_key);
void init_probe(struct Graph& G, int startNumber, int destNumber, const TFheGateBootstrappingCloudKeySet* EK, const TFheGateBootstrappingSecretKeySet *PK, Evaluator &eval, seal::RelinKeys& relin_keys, seal::PublicKey public_key, std::shared_ptr<seal::SEALContext> context, seal::SecretKey secret_key);
void probeMinCut(struct Graph& G, struct nodeList& N, vector<int> path, int dest, const TFheGateBootstrappingCloudKeySet* EK);
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
void returnInvestment(struct Graph& G, int startNumber, int destNumber, const TFheGateBootstrappingCloudKeySet* EK, const TFheGateBootstrappingSecretKeySet *PK, Evaluator &eval, seal::RelinKeys& relin_keys, seal::PublicKey public_key, std::shared_ptr<seal::SEALContext> context, seal::SecretKey secret_key);



vector<double> closeness(Graph& G, const TFheGateBootstrappingCloudKeySet* EK);
vector<double> harmonic(Graph& G, const TFheGateBootstrappingCloudKeySet* EK);
vector<double> betweenness(Graph& G, const TFheGateBootstrappingCloudKeySet* EK);
std::vector<double> getNormalizedDegree(struct Graph& G);
vector<double> normalizedCloseness(Graph& G, const TFheGateBootstrappingCloudKeySet* EK);
vector<double> normalizedHarmonic(Graph& G, const TFheGateBootstrappingCloudKeySet* EK);
vector<double> normalizedBetweenness(Graph& G, const TFheGateBootstrappingCloudKeySet* EK);
void extract2(struct Graph& G, vector<vector<int>>* T, struct nodeList& N, vector<int> path, int dest, const TFheGateBootstrappingCloudKeySet* EK);
//vector<double> somePathBetweennessCentrality(Graph& G, const TFheGateBootstrappingCloudKeySet* EK, int dest);
void addRandomlyOnlyEdges(struct Graph& G, int dummyEdgesNum, const TFheGateBootstrappingCloudKeySet* EK);
void addRandomlyEdgesNodes(struct Graph& G, int dummyNodesNum, int graphSize, const TFheGateBootstrappingCloudKeySet* EK, const TFheGateBootstrappingSecretKeySet *PK, seal::PublicKey public_key, std::shared_ptr<seal::SEALContext> context);
vector<double> allPathBetweennessCentrality(Graph& G, const TFheGateBootstrappingCloudKeySet* EK, int source, int dest);
vector<double> weightedPathBetweennessCentrality(Graph& G, const TFheGateBootstrappingCloudKeySet* EK,int source, int dest);
vector<double> someBetweennessCen(Graph &G, const TFheGateBootstrappingCloudKeySet* EK, int dest, set<int> &sourceNodeSet);
vector<double> somePathBetCen(Graph& G, const TFheGateBootstrappingCloudKeySet* EK, int dest, set<int> &sourceNodeSet);
void heuristicOnlyEdges2(struct Graph &G, int sourceNode, int destinationNode, const TFheGateBootstrappingCloudKeySet* EK);
void heuristicAddNodes(struct Graph &G, int destinationNode, int dummyNode, vector<double> betweennessCen, const TFheGateBootstrappingCloudKeySet* EK, const TFheGateBootstrappingSecretKeySet *PK, seal::PublicKey public_key, std::shared_ptr<seal::SEALContext> context);
void countTotalPath(struct Graph& G, int startNumber, int destNumber);
void changeGraph(struct Graph &G, int source);
void heuristicAddNodes2(struct Graph &G, int destinationNode, int dummyNode, vector<double> betweennessCen, const TFheGateBootstrappingCloudKeySet* EK, const TFheGateBootstrappingSecretKeySet *PK, seal::PublicKey public_key, std::shared_ptr<seal::SEALContext> context);
