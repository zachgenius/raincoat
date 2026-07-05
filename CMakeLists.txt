cmake_minimum_required(VERSION 3.16)
# C is enabled for the macOS interposer dylib (src/rc_interpose.c); harmless on Linux.
# VERSION must match kVersion in src/main.cpp.
project(raincoat VERSION 0.1.0 LANGUAGES CXX C)

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

# Sandbox backend: EXACTLY ONE implementation is linked per platform (the runner talks to
# the backend seam in backend.hpp, never to bwrap/sandbox-exec directly). Strip both from
# the glob, then add the right pair back. bwrap.cpp + backend_linux.cpp on Linux;
# seatbelt.cpp + backend_macos.cpp on macOS. (list(REMOVE_ITEM) on an absent path is a no-op.)
list(REMOVE_ITEM CORE_SOURCES
  "${CMAKE_SOURCE_DIR}/src/bwrap.cpp"
  "${CMAKE_SOURCE_DIR}/src/backend_linux.cpp"
  "${CMAKE_SOURCE_DIR}/src/seccomp_notify.cpp"
  "${CMAKE_SOURCE_DIR}/src/seatbelt.cpp"
  "${CMAKE_SOURCE_DIR}/src/backend_macos.cpp")
if(APPLE)
  list(APPEND CORE_SOURCES
    "${CMAKE_SOURCE_DIR}/src/seatbelt.cpp"
    "${CMAKE_SOURCE_DIR}/src/backend_macos.cpp")
else()
  # seccomp_notify uses <linux/seccomp.h> / <linux/filter.h> — Linux-only.
  list(APPEND CORE_SOURCES
    "${CMAKE_SOURCE_DIR}/src/bwrap.cpp"
    "${CMAKE_SOURCE_DIR}/src/backend_linux.cpp"
    "${CMAKE_SOURCE_DIR}/src/seccomp_notify.cpp")
endif()

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

# macOS identity interposer: a standalone dylib injected into the sandboxed child via
# DYLD_INSERT_LIBRARIES (see src/rc_interpose.c). Built next to the raincoat binary so the
# runner can locate it relative to its own executable path. Not part of raincoat_core.
if(APPLE)
  add_library(rc_interpose SHARED "${CMAKE_SOURCE_DIR}/src/rc_interpose.c")
  set_target_properties(rc_interpose PROPERTIES
    PREFIX "" OUTPUT_NAME "rc_interpose" SUFFIX ".dylib"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
  add_dependencies(raincoat rc_interpose)
endif()

# ---------------------------------------------------------------------------
# Install + packaging (CPack)
# ---------------------------------------------------------------------------
include(GNUInstallDirs)
install(TARGETS raincoat RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
if(APPLE)
  # The runner looks for the interposer next to its own binary first (dev builds), then at
  # ../lib/raincoat/ relative to the binary (installed layout) — see interpose_dylib_path().
  install(FILES "${CMAKE_BINARY_DIR}/rc_interpose.dylib"
          DESTINATION ${CMAKE_INSTALL_LIBDIR}/raincoat)
endif()

set(CPACK_PACKAGE_NAME "raincoat")
set(CPACK_PACKAGE_VENDOR "zachgenius")
set(CPACK_PACKAGE_CONTACT "https://github.com/zachgenius/raincoat")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY
    "Lightweight privacy sandbox for nosy CLI tools and AI agents")
set(CPACK_PACKAGE_HOMEPAGE_URL "https://github.com/zachgenius/raincoat")
set(CPACK_RESOURCE_FILE_README "${CMAKE_SOURCE_DIR}/README.md")
set(CPACK_STRIP_FILES TRUE)
# Debian: resolve libssl/libc automatically; bubblewrap is the hard runtime dep, pasta optional.
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
set(CPACK_DEBIAN_PACKAGE_DEPENDS "bubblewrap")
set(CPACK_DEBIAN_PACKAGE_RECOMMENDS "passt")
set(CPACK_DEBIAN_PACKAGE_SECTION "utils")
set(CPACK_RPM_PACKAGE_REQUIRES "bubblewrap")
set(CPACK_RPM_PACKAGE_SUGGESTS "passt")
set(CPACK_RPM_PACKAGE_LICENSE "GPL-3.0-or-later")
include(CPack)

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

# Backend-specific suites: the bwrap/font argv tests call build_bwrap_argv (only linked on
# Linux); the seatbelt SBPL test needs the macOS backend. Prune whichever the linked
# backend cannot satisfy so `ctest` is green on both platforms.
set(RC_LINUX_ONLY_TESTS
  test_bwrap test_bwrap_attack2_regression test_bwrap_font_mask_regression
  test_font_local_mask_missing_dir_regression test_font_local_share_leak_attack
  test_backend_golden_argv test_seccomp_notify)
set(RC_MACOS_ONLY_TESTS test_seatbelt)

foreach(test_src ${TEST_SOURCES})
  get_filename_component(test_name "${test_src}" NAME_WE)
  if(APPLE AND test_name IN_LIST RC_LINUX_ONLY_TESTS)
    continue()
  endif()
  if(NOT APPLE AND test_name IN_LIST RC_MACOS_ONLY_TESTS)
    continue()
  endif()
  add_executable(${test_name} "${test_src}")
  target_include_directories(${test_name} PRIVATE "${CMAKE_SOURCE_DIR}/src")
  target_compile_definitions(${test_name} PRIVATE RC_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
  target_link_libraries(${test_name} PRIVATE raincoat_core ${RC_GTEST_LIBS})
  # On macOS, a GoogleTest dylib in a non-standard prefix (e.g. conda/homebrew) is not
  # auto-added to the rpath when it sits in an implicit link dir, so bake its directory in
  # explicitly — otherwise `ctest` fails with a dyld "@rpath/libgtest… not loaded" error.
  if(APPLE AND TARGET GTest::gtest)
    set_target_properties(${test_name} PROPERTIES
      BUILD_RPATH "$<TARGET_FILE_DIR:GTest::gtest>")
  endif()
  add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()
