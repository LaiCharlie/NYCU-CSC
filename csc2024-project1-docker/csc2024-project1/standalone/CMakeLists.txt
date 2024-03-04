cmake_minimum_required(VERSION 3.24)

project(Standalone LANGUAGES CXX)

# --- Import tools ----

include(../cmake/tools.cmake)

# ---- Dependencies ----

include(../cmake/CPM.cmake)

CPMAddPackage(
  GITHUB_REPOSITORY jarro2783/cxxopts
  VERSION 3.1.1
  GIT_SHALLOW TRUE
  OPTIONS "CXXOPTS_BUILD_EXAMPLES NO" "CXXOPTS_BUILD_TESTS NO"
)

CPMAddPackage(NAME IPSecHijack SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/..)

# ---- Create standalone executables ----

add_executable(hijack ${CMAKE_CURRENT_SOURCE_DIR}/source/main.cpp)
set_target_properties(hijack PROPERTIES CXX_STANDARD 20 OUTPUT_NAME "hijack")
target_link_libraries(hijack IPSecHijack cxxopts)

add_executable(client ${CMAKE_CURRENT_SOURCE_DIR}/source/client.cpp)
set_target_properties(client PROPERTIES CXX_STANDARD 20 OUTPUT_NAME "client")
target_link_libraries(client IPSecHijack cxxopts)

add_executable(server ${CMAKE_CURRENT_SOURCE_DIR}/source/server.cpp)
set_target_properties(server PROPERTIES CXX_STANDARD 20 OUTPUT_NAME "server")
target_link_libraries(server IPSecHijack cxxopts)
