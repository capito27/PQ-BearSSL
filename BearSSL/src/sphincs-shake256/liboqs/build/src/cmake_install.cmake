# Install script for directory: /home/filipe/HEIG/cysec/TLS_STUFFS/PQ-BearSSL/BearSSL/src/sphincs-shake256/liboqs/src

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "Release")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "0")
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

# Set default install directory permissions.
if(NOT DEFINED CMAKE_OBJDUMP)
  set(CMAKE_OBJDUMP "/usr/bin/objdump")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE STATIC_LIBRARY FILES "/home/filipe/HEIG/cysec/TLS_STUFFS/PQ-BearSSL/BearSSL/src/sphincs-shake256/liboqs/build/lib/liboqs.a")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/liboqs/liboqsConfig.cmake")
    file(DIFFERENT EXPORT_FILE_CHANGED FILES
         "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/liboqs/liboqsConfig.cmake"
         "/home/filipe/HEIG/cysec/TLS_STUFFS/PQ-BearSSL/BearSSL/src/sphincs-shake256/liboqs/build/src/CMakeFiles/Export/lib/cmake/liboqs/liboqsConfig.cmake")
    if(EXPORT_FILE_CHANGED)
      file(GLOB OLD_CONFIG_FILES "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/liboqs/liboqsConfig-*.cmake")
      if(OLD_CONFIG_FILES)
        message(STATUS "Old export file \"$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/liboqs/liboqsConfig.cmake\" will be replaced.  Removing files [${OLD_CONFIG_FILES}].")
        file(REMOVE ${OLD_CONFIG_FILES})
      endif()
    endif()
  endif()
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/cmake/liboqs" TYPE FILE FILES "/home/filipe/HEIG/cysec/TLS_STUFFS/PQ-BearSSL/BearSSL/src/sphincs-shake256/liboqs/build/src/CMakeFiles/Export/lib/cmake/liboqs/liboqsConfig.cmake")
  if("${CMAKE_INSTALL_CONFIG_NAME}" MATCHES "^([Rr][Ee][Ll][Ee][Aa][Ss][Ee])$")
    file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/cmake/liboqs" TYPE FILE FILES "/home/filipe/HEIG/cysec/TLS_STUFFS/PQ-BearSSL/BearSSL/src/sphincs-shake256/liboqs/build/src/CMakeFiles/Export/lib/cmake/liboqs/liboqsConfig-release.cmake")
  endif()
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/oqs" TYPE FILE FILES
    "/home/filipe/HEIG/cysec/TLS_STUFFS/PQ-BearSSL/BearSSL/src/sphincs-shake256/liboqs/src/oqs.h"
    "/home/filipe/HEIG/cysec/TLS_STUFFS/PQ-BearSSL/BearSSL/src/sphincs-shake256/liboqs/src/common/common.h"
    "/home/filipe/HEIG/cysec/TLS_STUFFS/PQ-BearSSL/BearSSL/src/sphincs-shake256/liboqs/src/common/rand/rand.h"
    "/home/filipe/HEIG/cysec/TLS_STUFFS/PQ-BearSSL/BearSSL/src/sphincs-shake256/liboqs/src/common/aes/aes.h"
    "/home/filipe/HEIG/cysec/TLS_STUFFS/PQ-BearSSL/BearSSL/src/sphincs-shake256/liboqs/src/common/sha2/sha2.h"
    "/home/filipe/HEIG/cysec/TLS_STUFFS/PQ-BearSSL/BearSSL/src/sphincs-shake256/liboqs/src/common/sha3/sha3.h"
    "/home/filipe/HEIG/cysec/TLS_STUFFS/PQ-BearSSL/BearSSL/src/sphincs-shake256/liboqs/src/common/sha3/sha3x4.h"
    "/home/filipe/HEIG/cysec/TLS_STUFFS/PQ-BearSSL/BearSSL/src/sphincs-shake256/liboqs/src/kem/kem.h"
    "/home/filipe/HEIG/cysec/TLS_STUFFS/PQ-BearSSL/BearSSL/src/sphincs-shake256/liboqs/src/sig/sig.h"
    "/home/filipe/HEIG/cysec/TLS_STUFFS/PQ-BearSSL/BearSSL/src/sphincs-shake256/liboqs/src/sig/sphincs/sig_sphincs.h"
    "/home/filipe/HEIG/cysec/TLS_STUFFS/PQ-BearSSL/BearSSL/src/sphincs-shake256/liboqs/build/include/oqs/oqsconfig.h"
    )
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for each subdirectory.
  include("/home/filipe/HEIG/cysec/TLS_STUFFS/PQ-BearSSL/BearSSL/src/sphincs-shake256/liboqs/build/src/common/cmake_install.cmake")
  include("/home/filipe/HEIG/cysec/TLS_STUFFS/PQ-BearSSL/BearSSL/src/sphincs-shake256/liboqs/build/src/sig/sphincs/cmake_install.cmake")

endif()

