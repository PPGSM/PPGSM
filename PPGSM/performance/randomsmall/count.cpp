#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <utility>

using namespace std;

int main(int argc, char **argv){
        string inputFile = argv[1];
        ifstream openFile(inputFile);
	int edgeNum = 0;

        string buffer;

        while(openFile.peek() != EOF){
                getline(openFile, buffer);
                stringstream ss(buffer);

                string str;
                int start, end;
                while(ss>>str){
                    	int temp = stoi(str);
                	if(temp == 1){
				edgeNum++;
			}
		}
        }
        openFile.close();
	cout <<edgeNum <<endl;
	return 0;
}
