int degreeBased(Graph &G, int s, int f, double &totalTimeCost, vector<double> B, const TFheGateBootstrappingSecretKeySet *PK, const TFheGateBootstrappingCloudKeySet *EK);
int BFSattack(Graph &G, int s, int f, double &toalTimaCost, vector<double> B, const TFheGateBootstrappingSecretKeySet *PK, const TFheGateBootstrappingCloudKeySet *EK);
int DFSattack(Graph &G, int s, int f, double &totalTimeCost, vector<double> B, const TFheGateBootstrappingSecretKeySet *PK, const TFheGateBootstrappingCloudKeySet *EK);
int init_shortestPathattack(Graph &G, int s, int f, int minCut, const TFheGateBootstrappingSecretKeySet *PK, const TFheGateBootstrappingCloudKeySet *EK);
int restrictedDFSattack(Graph &G, int s, int f, double &totalTimeCost, vector<double> B, const TFheGateBootstrappingSecretKeySet *PK, const TFheGateBootstrappingCloudKeySet *EK);
