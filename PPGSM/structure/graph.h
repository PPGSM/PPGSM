#include <vector>
#include <set>
using namespace std;
void delete_graph(struct Graph& G);
void probe(struct Graph& G, int startNumber, int destNumber, Evaluator &eval, seal::RelinKeys& relin_keys, seal::PublicKey public_key, std::shared_ptr<seal::SEALContext> context, seal::SecretKey secret_key);
int minLength(struct Graph& G, int startNumber, int destNumber);
double mpl(struct Graph& G, int startNumber, int destNumber);
struct degree getDegree(struct Graph& G);
struct nodeList findNode(struct Graph &G, int nodeNumber);
void PrAtkSuccess(struct Graph& G, int startNumber, int destNumber, Evaluator &eval, seal::RelinKeys& relin_keys, seal::PublicKey public_key, std::shared_ptr<seal::SEALContext> context, seal::SecretKey secret_key);
void cumulPrAtkSuccess(struct Graph& G, int startNumber, Evaluator &eval, seal::RelinKeys& relin_keys, seal::PublicKey public_key, std::shared_ptr<seal::SEALContext> context, seal::SecretKey secret_key);
void returnInvestment(struct Graph& G, int startNumber, int destNumber, int target, Evaluator &eval, seal::RelinKeys& relin_keys, seal::PublicKey public_key, std::shared_ptr<seal::SEALContext> context, seal::SecretKey secret_key);
