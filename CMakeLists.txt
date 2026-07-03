cmake_minimum_required(VERSION 3.16)
project(raincoat CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif()

add_compile_options(-Wall -Wextra)

# ---------------------------------------------------------------------------
# Core static library: every src/*.cpp except main.cpp
# ---------------------------------------------------------------------------
file(GLOB CORE_SOURCES CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/src/*.cpp")
list(REMOVE_ITEM CORE_SOURCES "${CMAKE_SOURCE_DIR}/src/main.cpp")

add_library(raincoat_core STATIC ${CORE_SOURCES})
target_include_directories(raincoat_core PUBLIC "${CMAKE_SOURCE_DIR}/src")

# Egress bridge (phase 2) uses sockets + OpenSSL (HTTPS upstreams) and threads.
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)
target_link_libraries(raincoat_core PUBLIC OpenSSL::SSL OpenSSL::Crypto Threads::Threads)

# ---------------------------------------------------------------------------
# Executable
# ---------------------------------------------------------------------------
add_executable(raincoat "${CMAKE_SOURCE_DIR}/src/main.cpp")
target_link_libraries(raincoat PRIVATE raincoat_core)

# ---------------------------------------------------------------------------
# Tests (GoogleTest)
# ---------------------------------------------------------------------------
enable_testing()

find_package(Threads REQUIRED)

# Prefer find_package(GTest); fall back to the system static libs by path.
set(RC_GTEST_LIBS "")
find_package(GTest QUIET)
if(GTest_FOUND)
  set(RC_GTEST_LIBS GTest::gtest GTest::gtest_main Threads::Threads)
else()
  set(_gtest_dir "/usr/lib/x86_64-linux-gnu")
  find_library(RC_GTEST_LIB      NAMES gtest      PATHS ${_gtest_dir})
  find_library(RC_GTEST_MAIN_LIB NAMES gtest_main PATHS ${_gtest_dir})
  if(NOT RC_GTEST_LIB OR NOT RC_GTEST_MAIN_LIB)
    message(FATAL_ERROR "GoogleTest not found via find_package or in ${_gtest_dir}")
  endif()
  set(RC_GTEST_LIBS ${RC_GTEST_MAIN_LIB} ${RC_GTEST_LIB} Threads::Threads)
endif()

file(GLOB TEST_SOURCES CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/tests/test_*.cpp")
foreach(test_src ${TEST_SOURCES})
  get_filename_component(test_name "${test_src}" NAME_WE)
  add_executable(${test_name} "${test_src}")
  target_include_directories(${test_name} PRIVATE "${CMAKE_SOURCE_DIR}/src")
  target_compile_definitions(${test_name} PRIVATE RC_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
  target_link_libraries(${test_name} PRIVATE raincoat_core ${RC_GTEST_LIBS})
  add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()
