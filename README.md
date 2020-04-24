# PP-GSM
Privacy Preserving Graphical Security Model   

This software enables one to evaluate the security of a network system in a privacy preserving mannaer.

Prerequesites
- OS: Ubuntu 18.04 above   
- HE libraries: TFHE and SEAL homomorphic encryption (HE) have to be installed.    

1. Installating and Testing

Install the two HE libraries.    
To use PPGSM, install two homomorphic encrpytion libraries: TFHE and SEAL.   
  
1.1. Installing TFHE   

Get the TFHE installation file available at: https://github.com/tfhe/tfhe/tarball/master     
(Note that the TFHE github main version would have a problem on installing TFHE)   
Unzip the tar.gz file into a directory and go to the directory where README.md and LICENSE are.   
Then, make directory named 'build':   

    mkdir build   
  
Go to the 'build' directory:   

    cd build   
    
Then, make installation file in the build directory:   

    cmake ../src   
    
Finally, using commands below, install TFHE:    

    make    
    sudo make install   

1.2. Installing SEAL 

Get SEAL installation file: git clone https://github.com/microsoft/SEAL   
Go to the SEAL native directory:   

    cd SEAL/native   
    
Make 'build' directory, change directory and install:    

    mkdir build    
    cd build    
    make installation file: cmake ../src

Finally, install SEAL:    

    make    
    sudo make install       
   
2. Running testcode    
Install PP-GSM module:    

    git clone https://github.com/PPGSM/PPGSM
    
Move to PPGSM directory:   

    cd PPGSM/PPGSM
    
Compile test code:   

    cmake .   
    
Run compiled binary:   

    ./testPPGSM sampleData/graphinfo1 sampleData/graphinfo2 sampleData/graphinfo3   
   
Utilities

   A. User-side utilites (functions can found in utility/graph_client.h)   
    creating real/dummy node/edges   
    creating graph   
   
   B. Server-side utilites (functions can found in structure/graph.h)   
    probing encrypted graph   
    simple metrics: mincut, minlength, calculating degree vector   
    graph pruning operation   
    complex operations: probability of attack succeess, return on investment  
    centrality metrics: clossness/harmonic/etweenness centrality   
    heurisitc dummy node/edge addition   
