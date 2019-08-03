# ------------------------------------------------------------------------------
# CMakeLists.txt for aggresss/playground-crypto/tests
# ------------------------------------------------------------------------------

SUBDIRLIST(SUB_DIRS ${CMAKE_CURRENT_LIST_DIR})
foreach(subdir ${SUB_DIRS})
  if(EXISTS ${CMAKE_CURRENT_LIST_DIR}/${subdir}/CMakeLists.txt)
    add_subdirectory(${subdir})
  endif()
endforeach()