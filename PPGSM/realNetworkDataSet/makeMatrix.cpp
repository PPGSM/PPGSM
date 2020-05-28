#include <iostream>
#include <fstream>
#include <sstream>
#include <set>
#include <vector>
#include <string>
#include <utility>

using namespace std;

vector<pair<int,int>> nodes;

void addNodes(int a){
	int nodeSize = nodes.size();
	bool exist = false;
	for(int i=0;i<nodeSize;i++){
		if(nodes[i].second == a){
			exist = true;
			break;
		}
	}

	if(!exist){
		nodes.push_back(make_pair(nodeSize, a));
	}
}

int findIndex(int a){
	int nodeSize = nodes.size();
	int index;
	for(int i=0;i<nodeSize;i++){
		if(nodes[i].second == a){
			index = nodes[i].first;
			break;	
		}
	}
	return index;
}

int main(int argc, char **argv){
	vector<pair<int, int>> edges;

	string inputFile = argv[1];
	ifstream openFile(inputFile);

	string buffer;

	while(openFile.peek() != EOF){
		getline(openFile, buffer);
		stringstream ss(buffer);

		string str;
		int temp = 0;
		int start, end;
		while(ss>>str){
			if(temp == 0){
				start = stoi(str);
				addNodes(start);
				temp = 1;
			}	
			else{
				end = stoi(str);
				addNodes(end);
				temp = 0;
			}
		}

		pair<int, int> edge = make_pair(start, end);
		edges.push_back(edge);
	}
	
	openFile.close();

	int nodeSize = nodes.size();

	int **adjMat;
	adjMat = (int**) malloc (sizeof(int*) * nodeSize);
	for(int i=0;i<nodeSize;i++){
		adjMat[i] = (int *) malloc (sizeof(int) * nodeSize);
	}

	for(int i=0;i<nodeSize;i++){
		for(int j=0;j<nodeSize;j++){
			adjMat[i][j]=0;
		}
	}

	int edgeNum = edges.size();
	for(int i=0;i<edgeNum;i++){
		int start = edges[i].first;
		int end = edges[i].second;
		int startIndex = findIndex(start);
		int endIndex = findIndex(end);
		adjMat[startIndex][endIndex] = 1;	
	}	

	string outputFile = argv[2];
	ofstream writeFile(outputFile);
	for(int i=0;i<nodeSize;i++){
		for(int j=0;j<nodeSize;j++){
			writeFile << adjMat[i][j] <<" ";
		}
		writeFile <<endl;
	}
	writeFile.close();

	for(int i=0;i<nodeSize;i++){
		free(adjMat[i]);
	}
	free(adjMat);

	return 0;
}
