#include <tfhe/tfhe_io.h>
#include "seal/seal.h"

//#include <helib/FHE.h>
//#include <helib/EncryptedArray.h>

#include <vector>
#include <list>

using namespace seal;
// Adjacent list based approach
struct node{
	bool		 user;
	int		 NodeNumber;    // Corresponding node number.
	
	Ciphertext	 Weight;
	Ciphertext	 Impact;
	Ciphertext	 Pr;
	Ciphertext	 logPr;
	Ciphertext	 Patch;
	Ciphertext	 inversePatch;

	LweSample *T;
	std::list<struct Neighbor>* Neighbors;
};

struct Neighbor{
	int	   	 NodeNumber;
	LweSample* 	 T;
};

struct Graph{
	std::list<struct nodeList>* node;
};

struct nodeList{
	bool   unchangeable;
	bool   visited;
	struct node* node;
};

// Degree information
struct degree{
	std::vector<struct degInfo> Vin;  // in-degree information
	std::vector<struct degInfo> Vout; // out-degree information
};

struct degInfo{
	int   NodeNumber;
	int   Degree;
};

// Information structrue when reading file
struct TraitInfo{
	char* type;
	int   cost;
	int   impact;
	double   pr;
	double	 logPr;
	double	 patch;
	double	 inverse_patch;
};

struct DEdgeInfo{
	int   start;
	int   end;
	int   minHop;
};
struct RevBFSTreeNode
{
	int  nodeNum;

	bool visited;
	int  score;
	int  invInEdge;
	struct RevBFSTreeNode *REdge;
};
