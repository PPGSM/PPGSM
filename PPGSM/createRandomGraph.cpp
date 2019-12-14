#include <iostream>
#include <fstream>
#include <string>
#include <random>
#include <cstdlib>
#include <ctime>

using namespace std;

int main(){
	srand(time(NULL));
	string subtitle = "randomGraph10-";
	string title;
	for(int i=0;i<10000;i++){
		title = subtitle + to_string(i+1);
//		cout <<title <<endl;

		int AdjMat[10][10];
		for(int a=0;a<10;a++){
			for(int b=0;b<10;b++){
				if(a==b){
					AdjMat[a][b]=0;
				}
				else if(a>b){
					AdjMat[a][b] = AdjMat[b][a];
				}
				else{
					double temp = (double)rand() / RAND_MAX;
					if(temp<0.9){
						AdjMat[a][b]=0;
					}
					else{
						AdjMat[a][b]=1;
					}
				}
			}
		}

		ofstream out(title);
		for(int a=0;a<10;a++){
			for(int b=0;b<10;b++){
				out <<AdjMat[a][b] <<" ";
			}
			out <<endl;
		}
		out.close();

	}
	return 0;
}

