cmake_minimum_required(VERSION 3.12.4)

project(fimebpf)

include_directories(${SRC_FOLDER}/syscheckd/src/ebpf/src)
include_directories(${SRC_FOLDER}/external/falcolibs)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  add_library(fimebpf SHARED ${CMAKE_SOURCE_DIR}/src/ebpf/src/ebpf_whodata.cpp)

  find_library(SINSP_LIBRARY libsinsp.so PATHS ${SRC_FOLDER}/external/falcolibs NO_DEFAULT_PATH)
  find_library(SCAP_LIBRARY libscap.so PATHS ${SRC_FOLDER}/external/falcolibs NO_DEFAULT_PATH)

  if (SINSP_LIBRARY AND SCAP_LIBRARY)
    message(STATUS "Found sinsp: ${SINSP_LIBRARY}")
    message(STATUS "Found scap: ${SCAP_LIBRARY}")

    target_link_libraries(fimebpf ${SINSP_LIBRARY} ${SCAP_LIBRARY})
  else()
    message(FATAL_ERROR "Could not find sinsp or scap libraries")
  endif()
endif()