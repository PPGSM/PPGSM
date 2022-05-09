#include "seal/seal.h"
#include <list>
#include <vector>

using namespace seal;
// Adjacent list based approach
struct node {
  bool user;
  int NodeNumber; // Corresponding node number.

  Ciphertext Weight;
  Ciphertext Impact;
  Ciphertext Pr;
  Ciphertext logPr;
  Ciphertext Patch;
  Ciphertext inversePatch;
  Ciphertext T;

  // for test...
  double exactPr;
  double exactlogPr;

  std::list<struct Neighbor> *Neighbors;
};

struct Neighbor {
  int NodeNumber;
};

struct Graph {
  std::list<struct nodeList> *node;
};

struct nodeList {
  bool unchangeable;
  bool visited;
  struct node *node;
};

// Degree information
struct degree {
  std::vector<struct degInfo> Vin;  // in-degree information
  std::vector<struct degInfo> Vout; // out-degree information
};

struct degInfo {
  int NodeNumber;
  int Degree;
};

// Information structrue when reading file
struct TraitInfo {
  char *type;
  int cost;
  int impact;
  double pr;
  double logPr;
  double patch;
  double inverse_patch;
};

struct DEdgeInfo {
  int start;
  int end;
  int minHop;
};
struct RevBFSTreeNode {
  int nodeNum;

  bool visited;
  int score;
  int invInEdge;
  struct RevBFSTreeNode *REdge;
};
