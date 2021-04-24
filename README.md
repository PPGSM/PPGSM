# PP-GSM
Privacy Preserving Graphical Security Model   

This software enables one to evaluate the security of a network system in a privacy preserving mannaer.

Prerequesites
- OS: Ubuntu 18.04 above   
- HE libraries: SEAL have to be installed.    

1. Installating and Testing

Install the SEAL library.    
To use PPGSM, install a homomorphic encrpytion library which is SEAL.    

1.1. Installing SEAL 

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

    ./homomorphic_graph testData/[graph file name] testData/testnodetype_60 (testnodetype_103 for "realGraph") testData/testtypeinfo [security metric info]
   
Utilities

   A. User-side utilites (functions can found in utility/graph_client.h)
    calculating centrality metrics: betweenness centrality (for graph obfuscation)
    creating real/dummy node/edges   
    creating graph   
   
   B. Server-side utilites (functions can found in structure/graph.h)   
    probing encrypted graph   
    simple metrics: indeoendent attack success probability (ind ASP), return on investment (ROSI), attack cost & risk, cumulative attack success probabiltiy (cum ASP)
    heurisitc dummy node/edge addition
