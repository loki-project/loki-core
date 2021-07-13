# Copyright (c) 2018, The Loki Project
# Copyright (c) 2014-2019, The Monero Project
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are
# permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of
#    conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list
#    of conditions and the following disclaimer in the documentation and/or other
#    materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may be
#    used to endorse or promote products derived from this software without specific
#    prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
# THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
# THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

list(INSERT CMAKE_MODULE_PATH 0
  "${CMAKE_SOURCE_DIR}/cmake")

find_program(CCACHE_PROGRAM ccache)
if(CCACHE_PROGRAM)
  foreach(lang C CXX)
    if(NOT DEFINED CMAKE_${lang}_COMPILER_LAUNCHER AND NOT CMAKE_${lang}_COMPILER MATCHES ".*/ccache")
      message(STATUS "Enabling ccache for ${lang}")
      set(CMAKE_${lang}_COMPILER_LAUNCHER ${CCACHE_PROGRAM} CACHE STRING "")
    endif()
  endforeach()
endif()

cmake_minimum_required(VERSION 3.10)
message(STATUS "CMake version ${CMAKE_VERSION}")

# Has to be set before `project()`, and ignored on non-macos:
set(CMAKE_OSX_DEPLOYMENT_TARGET 10.12 CACHE STRING "macOS deployment target (Apple clang only)")

project(oxen
    VERSION 9.2.0
    LANGUAGES CXX C)
set(OXEN_RELEASE_CODENAME "Audacious Aurochs")

# String value to append to the full version string; this is intended to easily identify whether a
# binary was build from the release or development branches.  This should be permanently set to an
# empty string on `stable`, "-dev" on the `dev` branch, and can be set externally (via cmake
# arguments) where it makes sense to take some other branch release with an extra value.
if(NOT DEFINED OXEN_RELEASE_SUFFIX)
  set(OXEN_RELEASE_SUFFIX "-dev")
endif()

if(POLICY CMP0079)
  cmake_policy(SET CMP0079 NEW)
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)
if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.14)
  cmake_policy(SET CMP0083 NEW)
  include(CheckPIESupported)
  check_pie_supported(OUTPUT_VARIABLE pie_error LANGUAGES CXX C)
  if(NOT CMAKE_CXX_LINK_PIE_SUPPORTED)
    message(WARNING "PIE linking is not supported: ${pie_error}")
  endif()
else()
  message(WARNING "PIE disabled: cmake 3.14+ is required for proper PIE linking support")
endif()

include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)
include(CheckLinkerFlag)
include(CheckLibraryExists)
include(CheckFunctionExists)

function (add_c_flag_if_supported flag var)
  string(REPLACE "-" "_" supported ${flag}_c)
  check_c_compiler_flag(${flag} ${supported})
  if(${${supported}})
    set(${var} "${${var}} ${flag}" PARENT_SCOPE)
  endif()
endfunction()

function (add_cxx_flag_if_supported flag var)
  string(REPLACE "-" "_" supported ${flag}_cxx)
  check_cxx_compiler_flag(${flag} ${supported})
  if(${${supported}})
    set(${var} "${${var}} ${flag}" PARENT_SCOPE)
  endif()
endfunction()

function (add_linker_flag_if_supported flag var)
  string(REPLACE "-" "_" supported ${flag}_ld)
  string(REPLACE "," "_" supported ${flag}_ld)
  check_linker_flag(${flag} ${supported})
  if(${${supported}})
    set(${var} "${${var}} ${flag}" PARENT_SCOPE)
  endif()
endfunction()

function (add_definition_if_function_found function var)
  string(REPLACE "-" "_" supported ${function}_function)
  check_function_exists(${function} ${supported})
  if(${${supported}})
    add_definitions("-D${var}")
  endif()
endfunction()

function (add_definition_if_library_exists library function header var)
  string(REPLACE "-" "_" supported ${function}_library)
  check_library_exists(${library} ${function} ${header} ${supported})
  if(${${supported}})
    add_definitions("-D${var}")
  endif()
endfunction()

# Properly links a target to a list of library names by finding the given libraries.  Takes:
# - a target
# - a linktype (e.g. INTERFACE, PUBLIC, PRIVATE)
# - a library search path (or "" for defaults)
# - any number of library names
function(link_dep_libs target linktype libdirs)
  foreach(lib ${ARGN})
    find_library(link_lib-${lib} NAMES ${lib} PATHS ${libdirs})
    if(link_lib-${lib})
      target_link_libraries(${target} ${linktype} ${link_lib-${lib}})
    endif()
  endforeach()
endfunction()

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
  message(STATUS "Setting default build type: ${CMAKE_BUILD_TYPE}")
endif()

cmake_policy(SET CMP0069 NEW)
SET(CMAKE_POLICY_DEFAULT_CMP0069 NEW)
if(CMAKE_BUILD_TYPE STREQUAL Release AND NOT MINGW AND NOT ANDROID)
  set(USE_LTO_DEFAULT ON)
else()
  set(USE_LTO_DEFAULT OFF)
endif()
option(USE_LTO "Use Link-Time Optimization" ${USE_LTO_DEFAULT})

if(USE_LTO)
  include(CheckIPOSupported)
  check_ipo_supported(RESULT IPO_ENABLED OUTPUT ipo_error)
  if(IPO_ENABLED)
    message(STATUS "LTO enabled")
  else()
    message(WARNING "LTO not supported by compiler: ${ipo_error}")
  endif()
else()
  message(STATUS "LTO disabled")
  set(IPO_ENABLED OFF)
endif()

if(IPO_ENABLED AND NOT DEFINED CMAKE_INTERPROCEDURAL_OPTIMIZATION)
  set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON)
endif()

# On Darwin, ensure the user-defined paths are used to find PCSC
# before falling back to the system frameworks.
set(CMAKE_FIND_FRAMEWORK "LAST")

# ARCH defines the target architecture, either by an explicit identifier or
# one of the following two keywords. By default, ARCH a value of 'native':
# target arch = host arch, binary is not portable. When ARCH is set to the
# string 'default', no -march arg is passed, which creates a binary that is
# portable across processors in the same family as host processor.  In cases
# when ARCH is not set to an explicit identifier, cmake's builtin is used
# to identify the target architecture, to direct logic in this cmake script.
# Since ARCH is a cached variable, it will not be set on first cmake invocation.
if (NOT ARCH_ID)
if (NOT ARCH OR ARCH STREQUAL "" OR ARCH STREQUAL "native" OR ARCH STREQUAL "default")
  if(CMAKE_SYSTEM_PROCESSOR STREQUAL "")
    set(CMAKE_SYSTEM_PROCESSOR ${CMAKE_HOST_SYSTEM_PROCESSOR})
  endif()
  set(ARCH_ID "${CMAKE_SYSTEM_PROCESSOR}")
else()
  set(ARCH_ID "${ARCH}")
endif()
endif()
string(TOLOWER "${ARCH_ID}" ARM_ID)
string(SUBSTRING "${ARM_ID}" 0 3 ARM_TEST)
if (ARM_TEST STREQUAL "arm")
  set(ARM 1)
  string(SUBSTRING "${ARM_ID}" 0 5 ARM_TEST)
  if (ARM_TEST STREQUAL "armv6")
    set(ARM6 1)
  endif()
  if (ARM_TEST STREQUAL "armv7")
    set(ARM7 1)
  endif()
endif()

if (ARM_ID STREQUAL "aarch64" OR ARM_ID STREQUAL "arm64" OR ARM_ID STREQUAL "armv8-a")
  set(ARM 1)
  set(ARM8 1)
  set(ARCH "armv8-a")
endif()

if(ARCH_ID STREQUAL "ppc64le")
  set(PPC64LE 1)
  set(PPC64   0)
  set(PPC     0)
endif()

if(ARCH_ID STREQUAL "powerpc64" OR ARCH_ID STREQUAL "ppc64")
  set(PPC64LE 0)
  set(PPC64   1)
  set(PPC     0)
endif()

if(ARCH_ID STREQUAL "powerpc" OR ARCH_ID STREQUAL "ppc")
  set(PPC64LE 0)
  set(PPC64   0)
  set(PPC     1)
endif()

if(ARCH_ID STREQUAL "s390x")
  set(S390X 1)
endif()

# BUILD_TAG is used to select the build type to check for a new version
if(BUILD_TAG)
  message(STATUS "Building build tag ${BUILD_TAG}")
  add_definitions("-DBUILD_TAG=${BUILD_TAG}")
else()
  message(STATUS "Building without build tag")
endif()

enable_testing()

option(BUILD_DOCUMENTATION "Build the Doxygen documentation." ON)
option(BUILD_TESTS "Build tests." OFF)
if (BUILD_TESTS)
  add_definitions(-DUNIT_TEST)
endif()

OPTION(USE_DEVICE_TREZOR "Build Trezor support (currently non-functional)" OFF)

find_package(Git)
if(NOT MANUAL_SUBMODULES)
  if(GIT_FOUND)
    function (check_submodule relative_path)
      execute_process(COMMAND git rev-parse "HEAD" WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/${relative_path} OUTPUT_VARIABLE localHead)
      execute_process(COMMAND git rev-parse "HEAD:${relative_path}" WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} OUTPUT_VARIABLE checkedHead)
      string(COMPARE EQUAL "${localHead}" "${checkedHead}" upToDate)
      if (upToDate)
        message(STATUS "Submodule '${relative_path}' is up-to-date")
      else()
        message(FATAL_ERROR "Submodule '${relative_path}' is not up-to-date. Please update with\ngit submodule update --init --recursive\nor run cmake with -DMANUAL_SUBMODULES=1")
      endif()

      # Extra arguments check nested submodules
      foreach(submod ${ARGN})
        execute_process(COMMAND git rev-parse "HEAD" WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/${relative_path}/${submod} OUTPUT_VARIABLE localHead)
        execute_process(COMMAND git rev-parse "HEAD:${submod}" WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/${relative_path} OUTPUT_VARIABLE checkedHead)
        string(COMPARE EQUAL "${localHead}" "${checkedHead}" upToDate)
        if (NOT upToDate)
          message(FATAL_ERROR "Nested submodule '${relative_path}/${submod}' is not up-to-date. Please update with\ngit submodule update --init --recursive\nor run cmake with -DMANUAL_SUBMODULES=1")
        endif()
      endforeach()
    endfunction ()
    
    message(STATUS "Checking submodules")
    check_submodule(external/miniupnp)
    check_submodule(external/rapidjson)
    check_submodule(external/trezor-common)
    check_submodule(external/randomx)
    check_submodule(external/loki-mq cppzmq)
    check_submodule(external/SQLiteCpp)
    if(BUILD_TESTS)
      check_submodule(external/googletest)
    endif()
    check_submodule(external/uWebSockets uSockets)
    check_submodule(external/ghc-filesystem)
  endif()
endif()

# set this to 0 if per-block checkpoint needs to be disabled
option(PER_BLOCK_CHECKPOINT "Enables per-block checkpointing" ON)

list(INSERT CMAKE_MODULE_PATH 0
  "${CMAKE_SOURCE_DIR}/cmake")

option(BOOST_IGNORE_SYSTEM_PATHS "Ignore boost system paths for local boost installation" OFF)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

# Check whether we're on a 32-bit or 64-bit system
if(CMAKE_SIZEOF_VOID_P EQUAL "8")
  set(DEFAULT_BUILD_64 ON)
else()
  set(DEFAULT_BUILD_64 OFF)
endif()
option(BUILD_64 "Build for 64-bit? 'OFF' builds for 32-bit." ${DEFAULT_BUILD_64})

if(BUILD_64)
  set(ARCH_WIDTH "64")
else()
  set(ARCH_WIDTH "32")
endif()
message(STATUS "Building for a ${ARCH_WIDTH}-bit system")

# Check if we're on FreeBSD so we can exclude the local miniupnpc (it should be installed from ports instead)
# CMAKE_SYSTEM_NAME checks are commonly known, but specifically taken from libsdl's CMakeLists
if(CMAKE_SYSTEM_NAME MATCHES "kFreeBSD.*|FreeBSD")
  set(FREEBSD TRUE)
endif()

# Check if we're on DragonFly BSD. See the README.md for build instructions.
if(CMAKE_SYSTEM_NAME MATCHES "DragonFly.*")
  set(DRAGONFLY TRUE)
endif()

# Check if we're on OpenBSD. See the README.md for build instructions.
if(CMAKE_SYSTEM_NAME MATCHES "kOpenBSD.*|OpenBSD.*")
  set(OPENBSD TRUE)
endif()

# TODO: check bsdi, NetBSD, to see if they need the same FreeBSD changes
#
# elseif(CMAKE_SYSTEM_NAME MATCHES "kNetBSD.*|NetBSD.*")
#   set(NETBSD TRUE)
# elseif(CMAKE_SYSTEM_NAME MATCHES ".*BSDI.*")
#   set(BSDI TRUE)

include(cmake/check_for_std_filesystem.cmake)

include_directories(external/rapidjson/include src external)

if(APPLE)
  include_directories(SYSTEM /usr/include/malloc)
  if(POLICY CMP0042)
    cmake_policy(SET CMP0042 NEW)
  endif()
endif()

option(BUILD_STATIC_DEPS "Download, build and statically link against core dependencies" OFF)
if(BUILD_STATIC_DEPS)
  include(StaticBuild)
endif()

if(MSVC OR MINGW OR BUILD_STATIC_DEPS)
  set(DEFAULT_STATIC true)
else()
  set(DEFAULT_STATIC false)
endif()
option(STATIC "Try to link external dependencies statically, where possible" ${DEFAULT_STATIC})

if(BUILD_STATIC_DEPS AND NOT STATIC)
  message(FATAL_ERROR "Option BUILD_STATIC_DEPS requires STATIC be enabled as well")
endif()

option(BUILD_SHARED_LIBS "Build shared internal libraries" OFF)

if(MINGW)
  string(REGEX MATCH "^[^/]:/[^/]*" msys2_install_path "${CMAKE_C_COMPILER}")
  message(STATUS "MSYS location: ${msys2_install_path}")
  set(CMAKE_INCLUDE_PATH "${msys2_install_path}/mingw${ARCH_WIDTH}/include")
  # This is necessary because otherwise CMake will make Boost libraries -lfoo
  # rather than a full path. Unfortunately, this makes the shared libraries get
  # linked due to a bug in CMake which misses putting -static flags around the
  # -lfoo arguments.
  set(DEFLIB ${msys2_install_path}/mingw${ARCH_WIDTH}/lib)
  list(REMOVE_ITEM CMAKE_C_IMPLICIT_LINK_DIRECTORIES ${DEFLIB})
  list(REMOVE_ITEM CMAKE_CXX_IMPLICIT_LINK_DIRECTORIES ${DEFLIB})
endif()

if(STATIC)
  if(MSVC)
    set(CMAKE_FIND_LIBRARY_SUFFIXES .lib .dll.a .a ${CMAKE_FIND_LIBRARY_SUFFIXES})
  else()
    set(CMAKE_FIND_LIBRARY_SUFFIXES .a ${CMAKE_FIND_LIBRARY_SUFFIXES})
  endif()
endif()

if(SANITIZE)
  if (MSVC)
    message(FATAL_ERROR "Cannot sanitize with MSVC")
  else()
    message(STATUS "Using ASAN")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address")
  endif()
endif()

# Set default blockchain storage location:
# memory was the default in Cryptonote before Monero implemented LMDB, it still works but is unnecessary.
# set(DATABASE memory)
set(DATABASE lmdb)

if (DEFINED ENV{DATABASE})
  set(DATABASE $ENV{DATABASE})
  message(STATUS "DATABASE set: ${DATABASE}")
else()
  message(STATUS "Could not find DATABASE in env (not required unless you want to change database type from default: ${DATABASE})")
endif()

if (DATABASE STREQUAL "lmdb")
  message(STATUS "Using LMDB as default DB type")
  set(BLOCKCHAIN_DB "lmdb")
else()
  message(FATAL_ERROR "Invalid database type: ${DATABASE}")
endif()

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads)

if (APPLE AND NOT IOS)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=x86-64 -fvisibility=default")
  if (NOT OpenSSL_DIR)
      EXECUTE_PROCESS(COMMAND brew --prefix openssl
        OUTPUT_VARIABLE OPENSSL_ROOT_DIR
        OUTPUT_STRIP_TRAILING_WHITESPACE)
    message(STATUS "Using OpenSSL found at ${OPENSSL_ROOT_DIR}")
  endif()
endif()

if(BUILD_STATIC_DEPS)
  # SSL::* targets already set up
else()
  find_package(OpenSSL REQUIRED)
endif()
message(STATUS "Using OpenSSL include dir at ${OPENSSL_INCLUDE_DIR}")

if(MINGW)
  # OpenSSL doesn't seem to properly set up its dependencies on Windows, leading to linking errors
  target_link_libraries(OpenSSL::Crypto INTERFACE ws2_32)
endif()

add_definition_if_library_exists(c memset_s "string.h" HAVE_MEMSET_S)
add_definition_if_library_exists(c explicit_bzero "strings.h" HAVE_EXPLICIT_BZERO)
add_definition_if_function_found(strptime HAVE_STRPTIME)

# Generate header for embedded translations
add_subdirectory(translations)

add_library(miniupnpc INTERFACE)
add_library(systemd INTERFACE)  # Will do nothing unless we find and enable systemd support

if(NOT TARGET sodium)
# Allow -D DOWNLOAD_SODIUM=FORCE to download without even checking for a local libsodium
  option(DOWNLOAD_SODIUM "Allow libsodium to be downloaded and built locally if not found on the system" OFF)
  if(NOT DOWNLOAD_SODIUM STREQUAL "FORCE" AND NOT BUILD_STATIC_DEPS)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(SODIUM libsodium>=1.0.9 IMPORTED_TARGET)
  endif()

  add_library(sodium INTERFACE)
  if(SODIUM_FOUND AND NOT DOWNLOAD_SODIUM STREQUAL "FORCE" AND NOT BUILD_STATIC_DEPS)
    target_link_libraries(sodium INTERFACE PkgConfig::SODIUM)
  else()
    if(NOT DOWNLOAD_SODIUM AND NOT BUILD_STATIC_DEPS)
      message(FATAL_ERROR "Could not find libsodium >= 1.0.9; either install it on your system or use -DDOWNLOAD_SODIUM=ON to download and build an internal copy")
    endif()
    message(STATUS "Sodium >= 1.0.9 not found, but DOWNLOAD_SODIUM specified, so downloading it")
    include(DownloadLibSodium)
    target_link_libraries(sodium INTERFACE sodium_vendor)
  endif()

  # Need this target export so that loki-mq properly picks up sodium
  export(TARGETS sodium NAMESPACE sodium:: FILE sodium-exports.cmake)
endif()

if (NOT BUILD_STATIC_DEPS)
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(UNBOUND libunbound REQUIRED IMPORTED_TARGET)
  add_library(libunbound INTERFACE)
  target_link_libraries(libunbound INTERFACE PkgConfig::UNBOUND)
endif()

option(WITH_SYSTEMD "Attempts to link against and enable systemd daemon notification support" ON)
if (WITH_SYSTEMD AND NOT BUILD_STATIC_DEPS)
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(SYSTEMD libsystemd IMPORTED_TARGET)

    if(SYSTEMD_FOUND)
      target_compile_definitions(systemd INTERFACE ENABLE_SYSTEMD)
      target_link_libraries(systemd INTERFACE PkgConfig::SYSTEMD)
    elseif(CMAKE_SYSTEM_NAME STREQUAL Linux)
      message(WARNING "systemd not found; building without systemd support (use -DWITH_SYSTEMD=OFF to suppress this warning)")
    endif()
endif()


add_subdirectory(external)

target_compile_definitions(easylogging PRIVATE AUTO_INITIALIZE_EASYLOGGINGPP)

if(USE_DEVICE_TREZOR)
  include(CheckTrezor)
endif()

if(MSVC)
  add_definitions("/bigobj /MP /W3 /GS- /D_CRT_SECURE_NO_WARNINGS /wd4996 /wd4345 /D_WIN32_WINNT=0x0600 /DWIN32_LEAN_AND_MEAN /DGTEST_HAS_TR1_TUPLE=0 /FIinline_c.h /D__SSE4_1__")
  # set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /Dinline=__inline")
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /STACK:10485760")
  if(STATIC)
    foreach(VAR CMAKE_C_FLAGS_DEBUG CMAKE_CXX_FLAGS_DEBUG CMAKE_C_FLAGS_RELEASE CMAKE_CXX_FLAGS_RELEASE)
      string(REPLACE "/MD" "/MT" ${VAR} "${${VAR}}")
    endforeach()
  endif()
  include_directories(SYSTEM src/platform/msc)
else()
  include(TestCXXAcceptsFlag)
  if (NOT ARCH)
    set(ARCH native CACHE STRING "CPU to build for: -march value or 'default' to not pass -march at all")
  endif()
  message(STATUS "Building on ${CMAKE_SYSTEM_PROCESSOR} for ${ARCH}")
  if(ARCH STREQUAL "default")
    set(ARCH_FLAG "")
  elseif(PPC64LE)
    set(ARCH_FLAG "-mcpu=power8")
  elseif(PPC64)
    set(ARCH_FLAG "-mcpu=970")
  elseif(PPC)
    set(ARCH_FLAG "-mcpu=7400")
  elseif(IOS AND ARCH STREQUAL "arm64")
    message(STATUS "IOS: Changing arch from arm64 to armv8")
    set(ARCH_FLAG "-march=armv8")
  elseif(IOS AND ARCH STREQUAL "x86_64")
    message(STATUS "IOS: Changing arch from x86_64 to x86-64")
    set(ARCH_FLAG "-march=x86-64")
  else()
    set(ARCH_FLAG "-march=${ARCH}")
    if(ARCH STREQUAL "native")
      check_c_compiler_flag(-march=native CC_SUPPORTS_MARCH_NATIVE)
      if (NOT CC_SUPPORTS_MARCH_NATIVE)
        check_c_compiler_flag(-mtune=native CC_SUPPORTS_MTUNE_NATIVE)
        if (CC_SUPPORTS_MTUNE_NATIVE)
          set(ARCH_FLAG "-mtune=${ARCH}")
        else()
          set(ARCH_FLAG "")
        endif()
      endif()
    endif()
  endif()

  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${ARCH_FLAG}")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${ARCH_FLAG}")

  set(WARNINGS "-Wall -Wextra -Wpointer-arith -Wvla -Wwrite-strings -Wno-error=extra -Wno-error=deprecated-declarations -Wno-unused-parameter -Wno-unused-variable -Wno-error=unused-variable -Wno-error=uninitialized")

  option(WARNINGS_AS_ERRORS "Enable warning as errors" OFF)
  if(NOT MINGW AND WARNINGS_AS_ERRORS)
    set(WARNINGS_AS_ERRORS_FLAG "-Werror")
  endif()

  if(CMAKE_C_COMPILER_ID STREQUAL "Clang" OR CMAKE_C_COMPILER_ID STREQUAL "AppleClang")
    if(ARM)
      set(WARNINGS "${WARNINGS} -Wno-error=inline-asm")
    endif()
  else()
    set(WARNINGS "${WARNINGS} -Wlogical-op -Wno-error=maybe-uninitialized -Wno-error=cpp -Wno-error=logical-op")
  endif()
  if(MINGW)
    set(WARNINGS "${WARNINGS} -Wno-error=unused-value -Wno-error=unused-but-set-variable")
    set(MINGW_FLAG "${MINGW_FLAG} -DWIN32_LEAN_AND_MEAN")
    set(Boost_THREADAPI win32)
    include_directories(SYSTEM src/platform/mingw)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--stack,10485760")
    if(NOT BUILD_64)
      add_definitions(-DWINVER=0x0501 -D_WIN32_WINNT=0x0501)
    endif()
  endif()
  set(C_WARNINGS "-Waggregate-return -Wnested-externs -Wold-style-definition -Wstrict-prototypes")
  set(CXX_WARNINGS "-Wno-reorder -Wno-missing-field-initializers")

  option(COVERAGE "Enable profiling for test coverage report" 0)

  if(COVERAGE)
    message(STATUS "Building with profiling for test coverage report")
    set(COVERAGE_FLAGS "-fprofile-arcs -ftest-coverage --coverage")
  endif()

  # if those don't work for your compiler, single it out where appropriate
  if(CMAKE_BUILD_TYPE STREQUAL "Release" AND NOT OPENBSD)
    set(C_SECURITY_FLAGS "${C_SECURITY_FLAGS} -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=1")
    set(C_SECURITY_FLAGS "${C_SECURITY_FLAGS} -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=1")
    set(CXX_SECURITY_FLAGS "${CXX_SECURITY_FLAGS} -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=1")
  endif()

  # warnings
  add_c_flag_if_supported(-Wformat C_SECURITY_FLAGS)
  add_cxx_flag_if_supported(-Wformat CXX_SECURITY_FLAGS)
  add_c_flag_if_supported(-Wformat-security C_SECURITY_FLAGS)
  add_cxx_flag_if_supported(-Wformat-security CXX_SECURITY_FLAGS)

  # -fstack-protector
  if (NOT OPENBSD AND NOT (WIN32 AND (CMAKE_C_COMPILER_ID STREQUAL "GNU" AND CMAKE_C_COMPILER_VERSION VERSION_LESS 9.1)))
    add_c_flag_if_supported(-fstack-protector C_SECURITY_FLAGS)
    add_cxx_flag_if_supported(-fstack-protector CXX_SECURITY_FLAGS)
    add_c_flag_if_supported(-fstack-protector-strong C_SECURITY_FLAGS)
    add_cxx_flag_if_supported(-fstack-protector-strong CXX_SECURITY_FLAGS)
  endif()

  # -fno-stack-check
  if (IOS)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-stack-check")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-stack-check")
  endif()

  # New in GCC 8.2
  if (NOT OPENBSD AND NOT (WIN32 AND (CMAKE_C_COMPILER_ID STREQUAL "GNU" AND CMAKE_C_COMPILER_VERSION VERSION_LESS 9.1)))
    add_c_flag_if_supported(-fcf-protection=full C_SECURITY_FLAGS)
    add_cxx_flag_if_supported(-fcf-protection=full CXX_SECURITY_FLAGS)
  endif()
  if (NOT WIN32 AND NOT OPENBSD AND NOT APPLE)
    add_c_flag_if_supported(-fstack-clash-protection C_SECURITY_FLAGS)
    add_cxx_flag_if_supported(-fstack-clash-protection CXX_SECURITY_FLAGS)
  endif()

  # Removed in GCC 9.1 (or before ?), but still accepted, so spams the output
  if (NOT CMAKE_C_COMPILER_ID STREQUAL "GNU" OR CMAKE_C_COMPILER_VERSION VERSION_LESS 9.1)
    add_c_flag_if_supported(-mmitigate-rop C_SECURITY_FLAGS)
    add_cxx_flag_if_supported(-mmitigate-rop CXX_SECURITY_FLAGS)
  endif()

  # linker
  add_linker_flag_if_supported(-Wl,-z,relro LD_SECURITY_FLAGS)
  add_linker_flag_if_supported(-Wl,-z,now LD_SECURITY_FLAGS)
  add_linker_flag_if_supported(-Wl,-z,noexecstack noexecstack_SUPPORTED)
  if (noexecstack_SUPPORTED)
    set(LD_SECURITY_FLAGS "${LD_SECURITY_FLAGS} -Wl,-z,noexecstack")
  endif()
  add_linker_flag_if_supported(-Wl,-z,noexecheap noexecheap_SUPPORTED)
  if (noexecheap_SUPPORTED)
    set(LD_SECURITY_FLAGS "${LD_SECURITY_FLAGS} -Wl,-z,noexecheap")
  endif()

  if(BACKCOMPAT)
      add_linker_flag_if_supported(-Wl,--wrap=__divmoddi4 LD_BACKCOMPAT_FLAGS)
      add_linker_flag_if_supported(-Wl,--wrap=glob LD_BACKCOMPAT_FLAGS)
      message(STATUS "Using Lib C back compat flags: ${LD_BACKCOMPAT_FLAGS}")
  endif()

  # some windows linker bits
  if (WIN32)
    add_linker_flag_if_supported(-Wl,--dynamicbase LD_SECURITY_FLAGS)
    add_linker_flag_if_supported(-Wl,--nxcompat LD_SECURITY_FLAGS)
    add_linker_flag_if_supported(-Wl,--high-entropy-va LD_SECURITY_FLAGS)
  endif()

  message(STATUS "Using C security hardening flags: ${C_SECURITY_FLAGS}")
  message(STATUS "Using C++ security hardening flags: ${CXX_SECURITY_FLAGS}")
  message(STATUS "Using linker security hardening flags: ${LD_SECURITY_FLAGS}")

  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_GNU_SOURCE ${MINGW_FLAG} ${WARNINGS} ${C_WARNINGS} ${COVERAGE_FLAGS} ${C_SECURITY_FLAGS}")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_GNU_SOURCE ${MINGW_FLAG} ${WARNINGS} ${CXX_WARNINGS} ${COVERAGE_FLAGS} ${CXX_SECURITY_FLAGS}")
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${LD_SECURITY_FLAGS} ${LD_BACKCOMPAT_FLAGS}")

  if(ARM)
    message(STATUS "Setting FPU Flags for ARM Processors")

    #NB NEON hardware does not fully implement the IEEE 754 standard for floating-point arithmetic
    #Need custom assembly code to take full advantage of NEON SIMD

    #Cortex-A5/9  -mfpu=neon-fp16
    #Cortex-A7/15 -mfpu=neon-vfpv4
    #Cortex-A8    -mfpu=neon
    #ARMv8  	  -FP and SIMD on by default for all ARM8v-A series, NO -mfpu setting needed

    #For custom -mtune, processor IDs for ARMv8-A series:
    #0xd04 - Cortex-A35
    #0xd07 - Cortex-A57
    #0xd08 - Cortex-A72
    #0xd03 - Cortex-A73

    if(NOT ARM8)
      CHECK_CXX_ACCEPTS_FLAG(-mfpu=vfp3-d16 CXX_ACCEPTS_VFP3_D16)
      CHECK_CXX_ACCEPTS_FLAG(-mfpu=vfp4 CXX_ACCEPTS_VFP4)
      CHECK_CXX_ACCEPTS_FLAG(-mfloat-abi=hard CXX_ACCEPTS_MFLOAT_HARD)
      CHECK_CXX_ACCEPTS_FLAG(-mfloat-abi=softfp CXX_ACCEPTS_MFLOAT_SOFTFP)
    endif()

    if(ARM8)
      CHECK_CXX_ACCEPTS_FLAG(-mfix-cortex-a53-835769 CXX_ACCEPTS_MFIX_CORTEX_A53_835769)
      CHECK_CXX_ACCEPTS_FLAG(-mfix-cortex-a53-843419 CXX_ACCEPTS_MFIX_CORTEX_A53_843419)
    endif()

    if(ARM6)
      message(STATUS "Selecting VFP for ARMv6")
      set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mfpu=vfp")
      set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mfpu=vfp")
    endif(ARM6)

    if(ARM7)
      if(CXX_ACCEPTS_VFP3_D16 AND NOT CXX_ACCEPTS_VFP4)
        message(STATUS "Selecting VFP3 for ARMv7")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mfpu=vfp3-d16")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mfpu=vfp3-d16")
      endif()

      if(CXX_ACCEPTS_VFP4)
        message(STATUS "Selecting VFP4 for ARMv7")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mfpu=vfp4")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mfpu=vfp4")
      endif()

      if(CXX_ACCEPTS_MFLOAT_HARD)
        message(STATUS "Setting Hardware ABI for Floating Point")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mfloat-abi=hard")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mfloat-abi=hard")
      endif()

      if(CXX_ACCEPTS_MFLOAT_SOFTFP AND NOT CXX_ACCEPTS_MFLOAT_HARD)
        message(STATUS "Setting Software ABI for Floating Point")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mfloat-abi=softfp")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mfloat-abi=softfp")
      endif()
    endif(ARM7)

    if(ARM8)
      if(CXX_ACCEPTS_MFIX_CORTEX_A53_835769)
        message(STATUS "Enabling Cortex-A53 workaround 835769")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mfix-cortex-a53-835769")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mfix-cortex-a53-835769")
      endif()

      if(CXX_ACCEPTS_MFIX_CORTEX_A53_843419)
        message(STATUS "Enabling Cortex-A53 workaround 843419")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mfix-cortex-a53-843419")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mfix-cortex-a53-843419")
      endif()
    endif(ARM8)

  endif(ARM)

  if(APPLE)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fvisibility=default -DGTEST_HAS_TR1_TUPLE=0")
  endif()

  # At least some CLANGs default to not enough for monero
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -ftemplate-depth=900")

  if(STATIC)
    # STATIC already configures most deps to be linked in statically,
    # here we make more deps static if the platform permits it
    if (MINGW)
      # On Windows, this is as close to fully-static as we get:
      # this leaves only deps on /c/Windows/system32/*.dll
      set(STATIC_FLAGS "-static")
    elseif (NOT (APPLE OR FREEBSD OR OPENBSD OR DRAGONFLY))
      # On Linux, we don't support fully static build, but these can be static
      set(STATIC_FLAGS "-static-libgcc -static-libstdc++")
    endif()
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${STATIC_FLAGS} ")
  endif()
endif()



if (${BOOST_IGNORE_SYSTEM_PATHS} STREQUAL "ON")
  set(Boost_NO_SYSTEM_PATHS TRUE)
endif()

set(OLD_LIB_SUFFIXES ${CMAKE_FIND_LIBRARY_SUFFIXES})
if(STATIC)
  if(MINGW)
    set(CMAKE_FIND_LIBRARY_SUFFIXES .a)
    set(Boost_NO_BOOST_CMAKE ON)
  endif()

  set(Boost_USE_STATIC_LIBS ON)
  set(Boost_USE_STATIC_RUNTIME ON)
endif()
set(Boost_USE_MULTITHREADED TRUE) # Needed for macOS, at least, and won't hurt elsewhere

if(BUILD_STATIC_DEPS)
  # StaticBuild.cmake sets Boost targets up for us
else()
  find_package(Boost 1.58 QUIET REQUIRED COMPONENTS system thread serialization program_options)
endif()

set(CMAKE_FIND_LIBRARY_SUFFIXES ${OLD_LIB_SUFFIXES})
if(NOT Boost_FOUND)
  message(FATAL_ERROR "Could not find Boost libraries, please make sure you have installed Boost or libboost-all-dev (>=1.58) or the equivalent")
elseif(Boost_FOUND)
  message(STATUS "Found Boost Version: ${Boost_VERSION}")
  if (OPENSSL_VERSION VERSION_GREATER_EQUAL 1.1 AND (
        Boost_VERSION VERSION_LESS 1.62.0 OR (Boost_VERSION VERSION_GREATER 100000 AND Boost_VERSION VERSION_LESS 106200)))
      message(FATAL_ERROR "Boost ${Boost_VERSION} (older than 1.62) is too old to link with OpenSSL ${OPENSSL_VERSION} (1.1 or newer) found at ${OPENSSL_INCLUDE_DIR} and ${OPENSSL_LIBRARIES}. "
                          "Update Boost or install OpenSSL 1.0 and set path to it when running cmake: "
                          "cmake -DOPENSSL_ROOT_DIR='/usr/include/openssl-1.0'")
  endif()
endif()

# Interface target for random extra system libraries that we need to link everything against
add_library(extra INTERFACE)
target_link_libraries(extra INTERFACE ${CMAKE_DL_LIBS})
target_link_libraries(extra INTERFACE Boost::boost)
target_link_libraries(extra INTERFACE Threads::Threads)

if(APPLE AND BUILD_SHARED_LIBS)
  # Don't crap out on circular dependencies between internal libs on macOS when doing a shared build
  target_link_libraries(extra INTERFACE "-undefined dynamic_lookup")
endif()

# Interface target for ICU libs (if needed)
add_library(icu INTERFACE)


if(MINGW)
  set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Wa,-mbig-obj")
  target_link_libraries(extra INTERFACE mswsock ws2_32 iphlpapi crypt32 bcrypt)
  link_dep_libs(icu INTERFACE "" icuio icuin icuuc icudt icutu iconv)
elseif(FREEBSD)
  target_link_libraries(extra INTERFACE execinfo)
elseif(DRAGONFLY)
  find_library(COMPAT compat)
  target_link_libraries(extra INTERFACE ${COMPAT})
elseif(CMAKE_SYSTEM_NAME MATCHES "(SunOS|Solaris)")
  target_link_libraries(extra INTERFACE socket nsl resolv)
elseif(APPLE)
  find_library(COREFOUNDATION CoreFoundation)
  find_library(IOKIT IOKit)
  target_link_libraries(extra INTERFACE ${IOKIT} ${COREFOUNDATION})
elseif(NOT (MSVC OR APPLE OR OPENBSD OR ANDROID))
  find_library(RT rt)
  target_link_libraries(extra INTERFACE rt)
endif()

if (WIN32)
  target_link_libraries(extra INTERFACE setupapi)
endif()

if (BUILD_INTEGRATION)
  target_compile_definitions(extra INTERFACE OXEN_ENABLE_INTEGRATION_TEST_HOOKS)
else()
  option(USE_READLINE "Build with GNU readline support." ON)
  if(USE_READLINE AND BUILD_STATIC_DEPS)
    # readline target already set up
  elseif(USE_READLINE)
    find_package(Readline)
    if(READLINE_FOUND AND GNU_READLINE_FOUND)
      add_library(readline INTERFACE)
      target_link_libraries(readline INTERFACE ${GNU_READLINE_LIBRARY})
      target_include_directories(readline INTERFACE ${Readline_INCLUDE_DIR})
      target_compile_definitions(readline INTERFACE HAVE_READLINE)
      message(STATUS "Found readline library at: ${GNU_READLINE_LIBRARY}")
    else()
      message(STATUS "Could not find GNU readline library so building without readline support")
    endif()
  endif()
endif()

if(ANDROID)
  target_compile_options(extra INTERFACE "-Wno-error=user-defined-warnings")
endif()
if(CMAKE_C_COMPILER_ID STREQUAL "Clang" AND ARCH_WIDTH EQUAL "32" AND NOT IOS AND NOT FREEBSD)
  find_library(ATOMIC atomic)
  if (ATOMIC_FOUND)
    target_link_libraries(extra INTERFACE ${ATOMIC})
  endif()
endif()

add_subdirectory(contrib)
add_subdirectory(src)

if(BUILD_TESTS)
  message(STATUS "Building tests")
  add_subdirectory(tests)
else()
  message(STATUS "Not building tests")
endif()

if(BUILD_DOCUMENTATION)
  set(DOC_GRAPHS "YES" CACHE STRING "Create dependency graphs (needs graphviz)")
  set(DOC_FULLGRAPHS "NO" CACHE STRING "Create call/callee graphs (large)")

  find_program(DOT_PATH dot)

  if (DOT_PATH STREQUAL "DOT_PATH-NOTFOUND")
    message("Doxygen: graphviz not found - graphs disabled")
    set(DOC_GRAPHS "NO")
  endif()

  find_package(Doxygen)
  if(DOXYGEN_FOUND)
    configure_file("cmake/Doxyfile.in" "Doxyfile" @ONLY)
    configure_file("cmake/Doxygen.extra.css.in" "Doxygen.extra.css" @ONLY)
    add_custom_target(doc
      ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
      WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
      COMMENT "Generating API documentation with Doxygen.." VERBATIM)
  endif()
endif()

find_package(PythonInterp)
find_program(iwyu_tool_path NAMES iwyu_tool.py iwyu_tool)
if (iwyu_tool_path AND PYTHONINTERP_FOUND)
  add_custom_target(iwyu
    COMMAND "${PYTHON_EXECUTABLE}" "${iwyu_tool_path}" -p "${CMAKE_BINARY_DIR}" -- --no_fwd_decls
    COMMENT "Running include-what-you-use tool"
    VERBATIM
  )
endif()

# Set up a `make strip_binaries` target that strips built binaries.  This depends on all
# default-built binaries and strips them after build.  (To also build and strip debug utilities
# there is also a `make strip_binaries_all` target.)
get_property(oxen_exec_tgts_all GLOBAL PROPERTY oxen_executable_targets)
set(oxen_exec_tgts "")
set(strip_binaries "")
set(strip_binaries_all "")
foreach(tgt ${oxen_exec_tgts_all})
  list(APPEND strip_binaries_all COMMAND ${CMAKE_STRIP} $<TARGET_FILE:${tgt}>)
  # Look for a EXCLUDE_FROM_ALL property:
  get_property(tgt_excl_all TARGET ${tgt} PROPERTY EXCLUDE_FROM_ALL)
  # Also look for EXCLUDE_FROM_ALL on the target's source directory (this, unfortunately, is not
  # inherited into the target itself, hence we check both).
  get_property(tgt_dir TARGET ${tgt} PROPERTY SOURCE_DIR)
  get_property(tgt_dir_excl_all DIRECTORY ${tgt_dir} PROPERTY EXCLUDE_FROM_ALL)
  if (NOT tgt_excl_all AND NOT tgt_dir_excl_all)
    list(APPEND oxen_exec_tgts ${tgt})
    list(APPEND strip_binaries COMMAND ${CMAKE_STRIP} $<TARGET_FILE:${tgt}>)
  endif()
endforeach()
add_custom_target(strip_binaries ${strip_binaries} DEPENDS ${oxen_exec_tgts})
add_custom_target(strip_binaries_all ${strip_binaries_all} DEPENDS ${oxen_exec_tgts_all})

execute_process(COMMAND tar --version RESULT_VARIABLE tar_exit_code OUTPUT_VARIABLE tar_vers)
set(git_tag "-unknown")
if(GIT_FOUND)
  execute_process(COMMAND "${GIT_EXECUTABLE}" rev-parse --abbrev-ref HEAD RESULT_VARIABLE ret OUTPUT_VARIABLE branch OUTPUT_STRIP_TRAILING_WHITESPACE)
  if(NOT ret AND branch STREQUAL "stable")
    # Get the tag description; for a tagged release this will be just the tag (v1.2.3); for
    # something following a tag this will be something like "v1.2.3-2-abcdef" for something 2
    # commits beyond the tag, currently at commit "abcdef".
    execute_process(COMMAND "${GIT_EXECUTABLE}" describe --tags --abbrev=6 HEAD RESULT_VARIABLE ret OUTPUT_VARIABLE tag OUTPUT_STRIP_TRAILING_WHITESPACE)
    if(NOT ret AND tag MATCHES "v[0-9]+\\.[0-9]+\\.[0-9]+(-.*)")
      # We're building something following a tagged release, so append the post-version git tag info
      set(git_tag "${CMAKE_MATCH_1}")
    else()
      set(git_tag "") # No tag appended if we're building a tagged stable branch release
    endif()
  else()
    execute_process(COMMAND "${GIT_EXECUTABLE}" rev-parse --short=9 HEAD RESULT_VARIABLE ret OUTPUT_VARIABLE commithash OUTPUT_STRIP_TRAILING_WHITESPACE)
    if(NOT ret)
      set(git_tag "-${commithash}")
    endif()
  endif()
endif()

set(tar_os ${CMAKE_SYSTEM_NAME})
set(default_archive create_tarxz)
if(tar_os STREQUAL "Linux")
  set(tar_os "linux-${CMAKE_SYSTEM_PROCESSOR}")
elseif(tar_os STREQUAL "Darwin")
  set(tar_os "macos")
elseif(tar_os STREQUAL "Windows")
  if(CMAKE_CROSSCOMPILING AND ARCH_TRIPLET MATCHES i686-.*mingw)
    set(tar_os "win-x86")
  elseif(CMAKE_CROSSCOMPILING AND ARCH_TRIPLET MATCHES x86_64-.*mingw)
    set(tar_os "win-x64")
  else()
    set(tar_os "windows") # Don't know what arch
  endif()
  set(default_archive create_zip) # .tar.xz files are too scary for Windows users
endif()
set(tar_dir "oxen-${tar_os}-${PROJECT_VERSION}${OXEN_RELEASE_SUFFIX}${git_tag}")
add_custom_target(create_tarxz
  COMMAND ${CMAKE_COMMAND} -E rename bin "${tar_dir}"
  COMMAND ${CMAKE_COMMAND} -E tar cvJ "${tar_dir}.tar.xz" -- "${tar_dir}"
  COMMAND ${CMAKE_COMMAND} -E rename "${tar_dir}" bin
  DEPENDS ${oxen_exec_tgts})

add_custom_target(create_zip
  COMMAND ${CMAKE_COMMAND} -E rename bin "${tar_dir}"
  COMMAND ${CMAKE_COMMAND} -E tar cv "${tar_dir}.zip" --format=zip -- "${tar_dir}"
  COMMAND ${CMAKE_COMMAND} -E rename "${tar_dir}" bin
  DEPENDS ${oxen_exec_tgts})

add_custom_target(create_archive DEPENDS ${default_archive})
