void createNode(struct Graph &G, int nodeNumber, double weight, double impact, double pr, double logPr, double patch, double inv_patch, bool isUser, bool isTrue, seal::PublicKey public_key, std::shared_ptr<seal::SEALContext> context);
void createDummyNode(struct Graph &G, int weight, int impact, double pr, double logPr, double patch, double inv_patch, seal::PublicKey public_key, std::shared_ptr<seal::SEALContext> context);
void createEdge(struct node* N, int target, bool isTrue);
void createDummyEdge(struct Graph &G, int src, int target, bool isTrue);
void MakeGraph(Graph& G, char *Mat, char *NodeInfo, char *Trait, seal::PublicKey public_key, std::shared_ptr<seal::SEALContext> context);
void queryData(std::vector<std::string> &OSlist, int index, int NID, CKKSEncoder &encoder, Encryptor &encryptor);
void queryDataByFile(char* f, std::vector<std::string> &OSlist, CKKSEncoder &encoder, Encryptor &encryptor);
void createTopology(Graph &G);
std::vector<std::string> loadOSlist(std::string input);
