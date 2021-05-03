#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <queue>
#include <vector>
#include <cmath>
#include <algorithm>
#include <iostream>

#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>

#include "structure/struct.h"
#include "utility/graph_client.h"
#include "structure/graph.h"

using namespace std;
//calculate entropy of centralities by using Shannon Entropy
double getEntrophy(std::vector<double> L)		{
        double entrophy = 0;
        double b=2;					//initial value of b can also be 10
        int s = L.size();

	sort(L.begin(),L.end());
	
	std::vector<double> num;	
	int temp = 1;	

        for(int i=1; i<s; i++){
		if(L[i]==L[i-1]){
			temp++;
		}
		else{
                	num.push_back(temp);
			temp = 1;
		}
        }

	num.push_back(temp);
	int t = num.size();

	for(int i=0; i<t; i++){
		num[i] /= s;
	}

        for(int i=0; i<t; i++){
                entrophy += num[i]*log(1/num[i])/log(b);
        }
        return entrophy;
}

//calculate standard deviation of centralities.
double standardDeviation(std::vector<double> L){
	double V = 0;	
	double mean = 0;
	int S = L.size();
	for(int i = 0; i < S; i++){
		mean+=L[i];
	}
	mean/=(double)S;

	for(int i = 0; i < S; i++){
		V += (L[i]-mean) * (L[i]-mean);
	}
	V/=(double)S;
	return sqrt(V);
}

