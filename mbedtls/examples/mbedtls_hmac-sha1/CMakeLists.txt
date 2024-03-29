# ------------------------------------------------------------------------------
# CMakeLists.txt for aggresss/deps subdirectory
# ------------------------------------------------------------------------------

include_directories(${MBEDTLS_DIRS}/include)

string(REGEX MATCH "[^/]+$" SUBMODULE ${CMAKE_CURRENT_LIST_DIR})
option(${SUBMODULE} "Build ${SUBMODULE}" OFF)

file(GLOB SRCS_TEST RELATIVE ${CMAKE_CURRENT_LIST_DIR} *_test.c)
if(SRCS_TEST)
  file(GLOB SRCS_COMMON RELATIVE ${CMAKE_CURRENT_LIST_DIR} *.c)
  list(REMOVE_ITEM SRCS_COMMON ${SRCS_TEST})
  if(${SUBMODULE} OR BUILD_ALL)
    foreach(test_file ${SRCS_TEST})
      get_filename_component(test_case ${test_file} NAME_WE)
      # Build
      add_executable(${SUBMODULE}_${test_case} ${SRCS_COMMON} ${test_file})
      target_compile_options(${SUBMODULE}_${test_case} PRIVATE -std=gnu99)
      target_link_libraries(${SUBMODULE}_${test_case} PRIVATE MBEDTLS_CRYPTO_STATIC)
      # Test
      add_test(NAME ${SUBMODULE}_${test_case} COMMAND ${SUBMODULE}_${test_case})
    endforeach()
  endif()
endif()

