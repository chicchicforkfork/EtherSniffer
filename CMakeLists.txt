project(ether_sniffer)

cmake_minimum_required(VERSION 3.16)

set(CMAKE_CXX_FLAGS "-m64 -std=c++14")
add_compile_options(-W -Wall -g -fpermissive)

include(FetchContent)

FetchContent_Declare(sensordb
  GIT_REPOSITORY https://github.com/chicchicforkfork/SensorDB.git
  GIT_TAG        master
)
FetchContent_Declare(lockedhash
  GIT_REPOSITORY https://github.com/chicchicforkfork/LockedHash.git
  GIT_TAG        master
)
FetchContent_Declare(json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG        v3.9.1
)
FetchContent_Declare(spdlog
  GIT_REPOSITORY https://github.com/gabime/spdlog
  GIT_TAG        v1.9.2
)


FetchContent_MakeAvailable(sensordb lockedhash json spdlog)


##################################
# ether_sniffer exe
##################################
add_executable(ether_sniffer
  src/main.cpp
)

target_compile_options(ether_sniffer
PRIVATE
  -Wno-unused-function 
  -Wno-unused-but-set-variable 
  -Wno-unused-parameter
  -Wno-unused-variable
)
target_include_directories(ether_sniffer
PUBLIC
  src
  include
  ${lockedhash_SOURCE_DIR}/include
  ${json_SOURCE_DIR}/include
  ${smartio_SOURCE_DIR}/include
  ${spdlog_SOURCE_DIR}/include
)
target_link_libraries(ether_sniffer
PUBLIC
  spdlog
  pthread
  smartio
)


#add_subdirectory(examples)
#add_subdirectory(tests)
#add_subdirectory(http)