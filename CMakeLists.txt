project(IGCHook)


set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -fPIC")
add_subdirectory(3rdparty/PFishHook)


include_directories(${PROJECT_SOURCE_DIR}/3rdparty/PFishHook)

add_library(igchook SHARED hook_igc.cpp)
target_link_libraries(igchook PFishHook)