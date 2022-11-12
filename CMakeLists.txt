cmake_minimum_required(VERSION 3.10)
project(calculat0r VERSION 1.0)
add_executable(calculat0r calculat0r.cpp)

find_package(SEAL)
target_link_libraries(calculat0r SEAL::seal)
