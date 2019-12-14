cmake_minimum_required(VERSION 3.10)
project(Homomorphic_graph VERSION 1.0)
add_executable(homomorphic_graph main.cpp graph_client.cpp function.cpp encryption.cpp graph.cpp AdvSearch.cpp)

find_package(SEAL)
target_link_libraries(homomorphic_graph SEAL::seal tfhe-spqlios-fma)
