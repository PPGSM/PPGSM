#include <iostream>
#include <fstream>
#include <string>
#include <random>
#include <cstdlib>
#include <ctime>

using namespace std;

int main(){
	srand(time(NULL));
	string subtitle = "randomGraph-large";
	string title;
	for(int i=0;i<1;i++){
		title = subtitle;
//		cout <<title <<endl;

		int AdjMat[100][100];
		for(int a=0;a<100;a++){
			for(int b=0;b<100;b++){
				if(a==b){
					AdjMat[a][b]=0;
				}
				else if(a>b){
					AdjMat[a][b] = AdjMat[b][a];
				}
				else{
					double temp = (double)rand() / RAND_MAX;
					if(temp<0.85){
						AdjMat[a][b]=0;
					}
					else{
						AdjMat[a][b]=1;
					}
				}
			}
		}

		ofstream out(title);
		for(int a=0;a<100;a++){
			for(int b=0;b<100;b++){
				out <<AdjMat[a][b] <<" ";
			}
			out <<endl;
		}
		out.close();

	}
	return 0;
}

