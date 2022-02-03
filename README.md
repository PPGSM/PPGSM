# PP-GSM
Privacy Preserving Graphical Security Model   

This software enables one to evaluate the security of a network system in a privacy preserving mannaer.

## Project members
- Dongwon Lee, Sungkyunkwan University, Suwon, Republic of Korea
- Yongwoo Oh, Sungkyunkwan University, Suwon, Republic of Korea
- Hyoungshick Kim, Sungkyunkwan University, Suwon, Republic of Korea
- Jin B. Hong, University of Western Australia, Perth, Australia
- Dongseong Kim, University of Queensland, Brisbane, Australia

## Prerequesites
- OS: Ubuntu 18.04 above   
- HE libraries: SEAL have to be installed. (We use version 3.6.2 for implementation)


## Installation

Install the SEAL library.    
To use PPGSM, install a homomorphic encrpytion library which is SEAL.    

Get SEAL installation file: git clone https://github.com/microsoft/SEAL   
Go to the SEAL directory:   

    cd SEAL   
    
Enter following commands to install:    

    cmake -S . -B build    
    cmake --build build    
    sudo cmake --install build

We can find more details about SEAL installation in https://github.com/microsoft/SEAL.


## Test    

Install PP-GSM module:    

    git clone https://github.com/PPGSM/PPGSM
    
Move to PPGSM directory:   

    cd PPGSM/PPGSM
    
Compile test code:   

    cmake .
    make
    
Run compiled binary:   

    ./homomorphic_graph testData/[graph file name] testData/testnodetype_60 (testnodetype_103 for "realGraph") testData/testtypeinfo [security metric info]

There are "ind_poas", "rosi", "risk", and "cum_poas" as [security metric info] for calculating independent attack success probability, return on investment, attack cost & risk, and cumulative attack success probabiltiy, respectively.

## Utilities

   A. User-side utilites (functions can found in utility/graph_client.h)
    calculating centrality metrics: betweenness centrality (for graph obfuscation)
    creating real/dummy node/edges   
    creating graph   
   
   B. Server-side utilites (functions can found in structure/graph.h)   
    probing encrypted graph   
    simple metrics: indeoendent attack success probability (ind ASP), return on investment (ROSI), attack cost & risk, cumulative attack success probabiltiy (cum ASP)
    heurisitc dummy node/edge addition
