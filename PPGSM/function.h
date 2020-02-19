#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include "seal/seal.h"

void MakeGraph(Graph& G, char *Mat, char *NodeInfo, char *Trait, const TFheGateBootstrappingSecretKeySet *PK, seal::PublicKey public_key, std::shared_ptr<seal::SEALContext> context);
double getEntrophy(std::vector<double> L);
double standardDeviation(std::vector<double> L);
int sh(struct Graph& G, int a, int t, const TFheGateBootstrappingSecretKeySet *PK);
double dr(struct Graph& G, int a, int t, const TFheGateBootstrappingSecretKeySet *PK);
void dr_probeShortest(struct Graph& G, int &length, int &temp, int &DpathNum, int &pathNum, struct nodeList* N, LweSample* Tmp, int dest, const TFheGateBootstrappingSecretKeySet* PK);
double drShortest(struct Graph& G, int a, int t, const TFheGateBootstrappingSecretKeySet *PK);
void dr_probeLength(struct Graph& G, int &tempLength, int &tempDummyLength, int &DpathNum, int &pathNum, struct nodeList* N, LweSample* Tmp, int dest, const TFheGateBootstrappingSecretKeySet* PK);
double drLength(struct Graph& G, int a, int t, const TFheGateBootstrappingSecretKeySet *PK);
void dr_probeShortestLength(struct Graph& G, int &length, int &temp, int &tempLength, int &tempDummyLength,  int &DpathNum, int &pathNum, struct nodeList* N, LweSample* Tmp, int dest, const TFheGateBootstrappingSecretKeySet* PK);
double drShortestLength(struct Graph& G, int a, int t, const TFheGateBootstrappingSecretKeySet *PK);
void dr_probeLength_var(struct Graph& G, int &dummyNode, struct nodeList* N, LweSample* Tmp, int dest, const TFheGateBootstrappingSecretKeySet* PK);
int dEdge(struct Graph& G, int a, int t, const TFheGateBootstrappingSecretKeySet *PK);
int dNode(struct Graph& G, int a, int t, const TFheGateBootstrappingSecretKeySet *PK);
double dummyGeneratingCost(struct Graph& G, int a, int t, const TFheGateBootstrappingSecretKeySet *PK,  double w1, double w2);
void getDummyBetweenness(struct Graph& G, std::vector <double> B, double &dNode, double &tempDEdge, double &dEdge, struct nodeList* N, LweSample* Tmp, int dest, const TFheGateBootstrappingSecretKeySet* PK);
double dummyGeneratingCost2(struct Graph& G, int a, int t, const TFheGateBootstrappingSecretKeySet *PK, const TFheGateBootstrappingCloudKeySet *EK, double w1, double w2);
