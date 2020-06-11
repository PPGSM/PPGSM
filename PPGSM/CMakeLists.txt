cmake_minimum_required(VERSION 3.10)
project(Homomorphic_graph VERSION 1.0)
add_executable(homomorphic_graph main.cpp utility/graph_client.cpp structure/graph.cpp utility/AdvSearch.cpp)
find_package(SEAL)
target_link_libraries(homomorphic_graph SEAL::seal tfhe-spqlios-fma)

