# ------------------------------------------------------------------------------
# CMakeLists.txt for playground-crypto Project Top Level
# ------------------------------------------------------------------------------
cmake_minimum_required(VERSION 2.8)

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/CMake" ${CMAKE_MODULE_PATH})
include(Utilities)
include(GNUInstallDirs)

# ------------------------------------------------------------------------------
# Cross compile
# ------------------------------------------------------------------------------

if(TOOLCHAIN_PATH)
    string(REGEX REPLACE "[/]$" "" TOOLCHAIN_PATH_NO_SLASH ${TOOLCHAIN_PATH})
    set(TOOLCHAIN_PATH_WITH_SLASH "${TOOLCHAIN_PATH_NO_SLASH}/")
else()
    set(TOOLCHAIN_PATH_WITH_SLASH "")
endif()

# MUST before project()
if(CROSS_COMPILE)
  string(REGEX REPLACE "[-]$" "" CROSS_COMPILE_NO_MINUS ${CROSS_COMPILE})
  set(CMAKE_C_COMPILER ${TOOLCHAIN_PATH_WITH_SLASH}${CROSS_COMPILE_NO_MINUS}-gcc)
  set(CMAKE_CXX_COMPILER ${TOOLCHAIN_PATH_WITH_SLASH}${CROSS_COMPILE_NO_MINUS}-g++)
  set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
  set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
  set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
  set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

  if(TOOLCHAIN_PATH)
    find_program(CMAKE_AR ${CROSS_COMPILE_NO_MINUS}-ar PATHS ${TOOLCHAIN_PATH_WITH_SLASH})
    find_program(CMAKE_RANLIB ${CROSS_COMPILE_NO_MINUS}-ranlib PATHS ${TOOLCHAIN_PATH_WITH_SLASH})
  else()
    find_program(CMAKE_AR ${CROSS_COMPILE_NO_MINUS}-ar)
    find_program(CMAKE_RANLIB ${CROSS_COMPILE_NO_MINUS}-ranlib)
  endif(TOOLCHAIN_PATH)

  set(TOOLCHAIN_FILE "${CMAKE_CURRENT_BINARY_DIR}/toolchain.cmake")
  file(WRITE ${TOOLCHAIN_FILE}
"# ------------------------------------------------------------------------------
# toolchain.cmake
# ------------------------------------------------------------------------------
# this is required
set(CMAKE_SYSTEM_NAME Linux)
# specify the cross compiler
set(CMAKE_C_COMPILER ${TOOLCHAIN_PATH_WITH_SLASH}${CROSS_COMPILE_NO_MINUS}-gcc)
set(CMAKE_CXX_COMPILER ${TOOLCHAIN_PATH_WITH_SLASH}${CROSS_COMPILE_NO_MINUS}-g++)
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
\n"
  )

endif(CROSS_COMPILE)

# ------------------------------------------------------------------------------
# Project
# ------------------------------------------------------------------------------

project("playground-crypto" C)

# ------------------------------------------------------------------------------
# Get and Display infomation
# ------------------------------------------------------------------------------

message(STATUS "CMake version: " ${CMAKE_VERSION})
message(STATUS "CMake system name: " ${CMAKE_SYSTEM_NAME})
message(STATUS "C compiler: " ${CMAKE_C_COMPILER})
message(STATUS "CXX compiler: " ${CMAKE_CXX_COMPILER})

c_compiler_prefix(C_COMPILER_PREFIX)
if(C_COMPILER_PREFIX)
  message(STATUS "C compiler prefix: " ${C_COMPILER_PREFIX})
endif()

c_compiler_machine(C_COMPILER_MACHINE)
if(C_COMPILER_MACHINE)
  message(STATUS "C compiler machine infomation: " ${C_COMPILER_MACHINE})
endif()

# ------------------------------------------------------------------------------
# Build type
# ------------------------------------------------------------------------------

set(CMAKE_BUILD_TYPE ${CMAKE_BUILD_TYPE}
  CACHE STRING "Choose the type of build: None Debug Release Coverage" FORCE)

if(CMAKE_BUILD_TYPE)
  message(STATUS "CMake build type: " ${CMAKE_BUILD_TYPE})
endif()

if(CUSTOM_FLAGS)
  string(REPLACE "," " " CUSTOM_FLAGS_WITH_SPACE ${CUSTOM_FLAGS})
endif()

# Default C / CXX flags
if (NOT CMAKE_BUILD_TYPE)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${CUSTOM_FLAGS_WITH_SPACE} -Wall")
endif()

set(CMAKE_C_FLAGS_DEBUG "${CUSTOM_FLAGS_WITH_SPACE} -g -ggdb -O0 -Wall")
set(CMAKE_C_FLAGS_RELEASE "${CUSTOM_FLAGS_WITH_SPACE} -O3 -DNDEBUG  -Wall")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -DDEFAULT_LOG_LEVEL=LOG_LEVEL_INFO")
set(CMAKE_C_FLAGS_COVERAGE "${CMAKE_C_FLAGS_DEBUG} -fprofile-arcs -ftest-coverage")

set(CMAKE_CXX_FLAGS ${CMAKE_C_FLAGS})
set(CMAKE_CXX_FLAGS_DEBUG ${CMAKE_C_FLAGS_DEBUG})
set(CMAKE_CXX_FLAGS_RELEASE ${CMAKE_C_FLAGS_RELEASE})
set(CMAKE_CXX_FLAGS_COVERAGE ${CMAKE_C_FLAGS_COVERAGE})

# ------------------------------------------------------------------------------
# Version
# ------------------------------------------------------------------------------

set(VERSION_MAJOR 0)
set(VERSION_MINOR 0)
set(VERSION_PATCH 1)
set(RELEASE_VERSION ${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH})
message(STATUS "${PROJECT_NAME} release version: " ${RELEASE_VERSION})

get_commit_id(BUILD_VERSION)
if(BUILD_VERSION)
  message(STATUS "${PROJECT_NAME} build version: " ${BUILD_VERSION})
endif()

# ------------------------------------------------------------------------------
# target static and shared
# ------------------------------------------------------------------------------

option(BUILD_STATIC "Build static library." ON)
option(BUILD_SHARED "Build shared library." OFF)

if (NOT BUILD_STATIC AND NOT BUILD_SHARED)
  message(FATAL_ERROR "Need to choose static or shared build!")
endif()

# ------------------------------------------------------------------------------
# Subdirectory
# ------------------------------------------------------------------------------

add_subdirectory(third_party)
add_subdirectory(tests)

# ------------------------------------------------------------------------------
# Test
# ------------------------------------------------------------------------------

option(ENABLE_TESTING "Build tests." ON)

if(ENABLE_TESTING)
  find_program(VALGRIND valgrind)
  if(VALGRIND)
    # Ctest configuration variables must be set BEFORE include(Ctest)
    set(MEMORYCHECK_COMMAND ${VALGRIND})
    # Check process children and give detail for each leak
    set(MEMORYCHECK_COMMAND_OPTIONS
      "${MEMORYCHECK_COMMAND_OPTIONS} --leak-check=yes --show-reachable=no --undef-value-errors=no")
    set(MEMORYCHECK_COMMAND_OPTIONS
      "${MEMORYCHECK_COMMAND_OPTIONS} --trace-children=yes --track-fds=no --track-origins=no")
    # Set error code.
    set(MEMORYCHECK_COMMAND_OPTIONS
      "${MEMORYCHECK_COMMAND_OPTIONS} --error-exitcode=255")
    # Generate suppression hint.
    set(MEMORYCHECK_COMMAND_OPTIONS
      "${MEMORYCHECK_COMMAND_OPTIONS} --gen-suppressions=all")
    # Set suppression file
    set(MEMORYCHECK_COMMAND_OPTIONS
      "${MEMORYCHECK_COMMAND_OPTIONS} --suppressions=${CMAKE_CURRENT_LIST_DIR}/valgrind.supp")
  endif()
  include (CTest)
  enable_testing()
  add_subdirectory(tests)
endif()

