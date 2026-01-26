#  Copyright (c) 2018, Facebook, Inc.
#  All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.
#
# Functions for building granular fizz libraries.

# Install header files preserving directory structure
# Similar to folly's auto_install_files()
function(fizz_install_headers rootName rootDir)
  file(TO_CMAKE_PATH "${rootDir}" rootDir)
  string(LENGTH "${rootDir}" rootDirLength)
  foreach(fil ${ARGN})
    file(TO_CMAKE_PATH "${fil}" filePath)
    string(FIND "${filePath}" "/" rIdx REVERSE)
    if(rIdx EQUAL -1)
      continue()
    endif()
    string(SUBSTRING "${filePath}" 0 ${rIdx} filePath)

    string(LENGTH "${filePath}" filePathLength)
    string(FIND "${filePath}" "${rootDir}" rIdx)
    if(rIdx EQUAL 0)
      math(EXPR filePathLength "${filePathLength} - ${rootDirLength}")
      string(SUBSTRING "${filePath}" ${rootDirLength} ${filePathLength} fileGroup)
      install(FILES ${fil}
              DESTINATION ${INCLUDE_INSTALL_DIR}/${rootName}${fileGroup})
    endif()
  endforeach()
endfunction()

# Initialize global properties for tracking targets and deferred dependencies
set_property(GLOBAL PROPERTY FIZZ_COMPONENT_TARGETS)
set_property(GLOBAL PROPERTY FIZZ_DEFERRED_DEPS)
set_property(GLOBAL PROPERTY FIZZ_GRANULAR_INTERFACE_TARGETS)

# Define a granular fizz library that:
# 1. Compiles sources ONCE via OBJECT library
# 2. Creates a STATIC library for individual linking
# 3. Defers internal fizz deps to be resolved later
# 4. Tracks OBJECT target for monolithic aggregation
#
# Usage:
#   fizz_add_library(fizz_crypto_hkdf
#     SRCS Hkdf.cpp
#     DEPS fizz_crypto_hasher              # Private dependencies
#     EXPORTED_DEPS fizz_crypto_crypto     # Public dependencies (propagated)
#     EXTERNAL_DEPS ${SOME_LIBRARY}        # External library dependencies
#   )
function(fizz_add_library _target_name)
  cmake_parse_arguments(
    FIZZ_LIB
    ""                                      # Options (boolean flags)
    ""                                      # Single-value args
    "SRCS;DEPS;EXPORTED_DEPS;EXTERNAL_DEPS" # Multi-value args
    ${ARGN}
  )

  set(_sources ${FIZZ_LIB_SRCS})
  if(NOT _sources)
    # Legacy support: if no SRCS keyword, treat remaining args as sources
    set(_sources ${FIZZ_LIB_UNPARSED_ARGUMENTS})
  endif()

  # Object library name - used for monolithic aggregation
  set(_obj_target "${_target_name}_obj")

  # Skip if no sources (header-only library)
  list(LENGTH _sources _src_count)
  if(_src_count EQUAL 0)
    # Header-only: create INTERFACE library
    add_library(${_target_name} INTERFACE)
    target_include_directories(${_target_name}
      INTERFACE
        $<BUILD_INTERFACE:${FIZZ_BASE_DIR}>
        $<BUILD_INTERFACE:${FIZZ_GENERATED_DIR}>
        $<INSTALL_INTERFACE:${INCLUDE_INSTALL_DIR}>
    )

    # Link exported deps for INTERFACE libraries
    if(FIZZ_LIB_EXPORTED_DEPS)
      target_link_libraries(${_target_name} INTERFACE ${FIZZ_LIB_EXPORTED_DEPS})
    endif()
    if(FIZZ_LIB_EXTERNAL_DEPS)
      target_link_libraries(${_target_name} INTERFACE ${FIZZ_LIB_EXTERNAL_DEPS})
    endif()

    install(TARGETS ${_target_name} EXPORT fizz-exports)
    add_library(fizz::${_target_name} ALIAS ${_target_name})
    return()
  endif()

  # 1. Create OBJECT library (compiles sources once)
  add_library(${_obj_target} OBJECT ${_sources})

  if(BUILD_SHARED_LIBS)
    set_property(TARGET ${_obj_target} PROPERTY POSITION_INDEPENDENT_CODE ON)
  endif()

  target_include_directories(${_obj_target}
    PUBLIC
      $<BUILD_INTERFACE:${FIZZ_BASE_DIR}>
      $<BUILD_INTERFACE:${FIZZ_GENERATED_DIR}>
      $<INSTALL_INTERFACE:${INCLUDE_INSTALL_DIR}>
      ${FOLLY_INCLUDE_DIR}
      ${OPENSSL_INCLUDE_DIR}
      ${sodium_INCLUDE_DIR}
      ${ZSTD_INCLUDE_DIR}
    PRIVATE
      ${GLOG_INCLUDE_DIRS}
      ${FIZZ_INCLUDE_DIRECTORIES}
  )

  target_compile_features(${_obj_target} PUBLIC cxx_std_20)

  # Link external dependencies on OBJECT library
  target_link_libraries(${_obj_target}
    PUBLIC
      ${OPENSSL_LIBRARIES}
      sodium
      Threads::Threads
    PRIVATE
      ${GLOG_LIBRARIES}
      ${GFLAGS_LIBRARIES}
      ${FIZZ_LINK_LIBRARIES}
      ${CMAKE_DL_LIBS}
      ${LIBRT_LIBRARIES}
  )

  # Link explicit external deps
  if(FIZZ_LIB_EXTERNAL_DEPS)
    target_link_libraries(${_obj_target} PUBLIC ${FIZZ_LIB_EXTERNAL_DEPS})
  endif()

  # Separate fizz internal deps (defer) from external deps (link immediately)
  set(_immediate_deps "")
  set(_fizz_deps "")
  foreach(_dep IN LISTS FIZZ_LIB_EXPORTED_DEPS)
    if(_dep MATCHES "^fizz_")
      list(APPEND _fizz_deps ${_dep})
    else()
      # Folly::*, external libs, etc. - link immediately
      list(APPEND _immediate_deps ${_dep})
    endif()
  endforeach()

  # Debug output
  message(STATUS "fizz_add_library(${_target_name})")
  message(STATUS "  EXPORTED_DEPS: ${FIZZ_LIB_EXPORTED_DEPS}")
  message(STATUS "  Immediate deps: ${_immediate_deps}")
  message(STATUS "  Deferred fizz deps: ${_fizz_deps}")

  # Link non-fizz deps immediately - they provide include paths needed at compile time
  if(_immediate_deps)
    target_link_libraries(${_obj_target} PUBLIC ${_immediate_deps})
  endif()

  # For shared builds: link Folly::folly to OBJECT libraries to get transitive
  # includes (Boost, etc.). We can't link fizz internal deps because they're
  # INTERFACE libraries linking to monolithic fizz, creating cycles.
  # Also link optional dependencies (OQS, aegis) for headers that need them.
  if(BUILD_SHARED_LIBS)
    target_link_libraries(${_obj_target} PUBLIC Folly::folly)
    if(liboqs_FOUND)
      target_link_libraries(${_obj_target} PUBLIC OQS::oqs)
    endif()
    if(aegis_FOUND)
      target_link_libraries(${_obj_target} PUBLIC aegis::aegis)
    endif()
  endif()

  # Defer internal fizz dependencies until all targets are created
  # Only for static builds - in shared builds, fizz internal deps are INTERFACE
  # libraries linking to monolithic fizz, which would create cycles
  if(NOT BUILD_SHARED_LIBS)
    if(_fizz_deps)
      list(JOIN _fizz_deps "," _deps_str)
      set_property(GLOBAL APPEND PROPERTY FIZZ_DEFERRED_DEPS
        "${_obj_target}|PUBLIC|${_deps_str}"
      )
    endif()
    if(FIZZ_LIB_DEPS)
      list(JOIN FIZZ_LIB_DEPS "," _deps_str)
      set_property(GLOBAL APPEND PROPERTY FIZZ_DEFERRED_DEPS
        "${_obj_target}|PRIVATE|${_deps_str}"
      )
    endif()
  endif()

  # Track OBJECT target for monolithic aggregation
  set_property(GLOBAL APPEND PROPERTY FIZZ_COMPONENT_TARGETS ${_obj_target})

  # 2. Create the granular library target
  if(BUILD_SHARED_LIBS)
    # For shared builds: create INTERFACE library that will link to monolithic fizz
    add_library(${_target_name} INTERFACE)

    target_include_directories(${_target_name}
      INTERFACE
        $<BUILD_INTERFACE:${FIZZ_BASE_DIR}>
        $<BUILD_INTERFACE:${FIZZ_GENERATED_DIR}>
        $<INSTALL_INTERFACE:${INCLUDE_INSTALL_DIR}>
    )

    # Track this target to link to fizz after monolithic library is created
    set_property(GLOBAL APPEND PROPERTY FIZZ_GRANULAR_INTERFACE_TARGETS ${_target_name})

    install(TARGETS ${_target_name} EXPORT fizz-exports)
  else()
    # For static builds: create STATIC library
    add_library(${_target_name} STATIC $<TARGET_OBJECTS:${_obj_target}>)

    target_include_directories(${_target_name}
      PUBLIC
        $<BUILD_INTERFACE:${FIZZ_BASE_DIR}>
        $<BUILD_INTERFACE:${FIZZ_GENERATED_DIR}>
        $<INSTALL_INTERFACE:${INCLUDE_INSTALL_DIR}>
        ${FOLLY_INCLUDE_DIR}
        ${OPENSSL_INCLUDE_DIR}
        ${sodium_INCLUDE_DIR}
        ${ZSTD_INCLUDE_DIR}
      PRIVATE
        ${GLOG_INCLUDE_DIRS}
        ${FIZZ_INCLUDE_DIRECTORIES}
    )

    target_compile_features(${_target_name} PUBLIC cxx_std_20)

    # Link external dependencies on STATIC library
    target_link_libraries(${_target_name}
      PUBLIC
        ${OPENSSL_LIBRARIES}
        sodium
        Threads::Threads
      PRIVATE
        ${GLOG_LIBRARIES}
        ${GFLAGS_LIBRARIES}
        ${FIZZ_LINK_LIBRARIES}
        ${CMAKE_DL_LIBS}
        ${LIBRT_LIBRARIES}
    )

    # Link explicit external deps
    if(FIZZ_LIB_EXTERNAL_DEPS)
      target_link_libraries(${_target_name} PUBLIC ${FIZZ_LIB_EXTERNAL_DEPS})
    endif()

    # Link non-fizz deps immediately (reuse _immediate_deps computed above)
    if(_immediate_deps)
      target_link_libraries(${_target_name} PUBLIC ${_immediate_deps})
    endif()

    # Defer internal fizz dependencies for STATIC library too (reuse _fizz_deps)
    if(_fizz_deps)
      list(JOIN _fizz_deps "," _deps_str)
      set_property(GLOBAL APPEND PROPERTY FIZZ_DEFERRED_DEPS
        "${_target_name}|PUBLIC|${_deps_str}"
      )
    endif()
    if(FIZZ_LIB_DEPS)
      list(JOIN FIZZ_LIB_DEPS "," _deps_str)
      set_property(GLOBAL APPEND PROPERTY FIZZ_DEFERRED_DEPS
        "${_target_name}|PRIVATE|${_deps_str}"
      )
    endif()

    install(
      TARGETS ${_target_name}
      EXPORT fizz-exports
      LIBRARY DESTINATION ${LIB_INSTALL_DIR}
      ARCHIVE DESTINATION ${LIB_INSTALL_DIR}
    )
  endif()

  # Create alias for the library
  add_library(fizz::${_target_name} ALIAS ${_target_name})
endfunction()

# Resolve all deferred dependencies after all targets have been created
# Call this after all add_subdirectory() calls and fizz_create_monolithic_library()
function(fizz_resolve_deferred_dependencies)
  # Allow linking targets defined in other directories
  cmake_policy(SET CMP0079 NEW)

  get_property(_deferred_deps GLOBAL PROPERTY FIZZ_DEFERRED_DEPS)

  foreach(_spec IN LISTS _deferred_deps)
    # Parse the spec: "target|visibility|dep1,dep2,..."
    string(REPLACE "|" ";" _parts "${_spec}")
    list(LENGTH _parts _len)
    if(_len LESS 3)
      continue()
    endif()

    list(GET _parts 0 _target)
    list(GET _parts 1 _visibility)
    list(GET _parts 2 _deps_str)

    # Split deps by comma
    string(REPLACE "," ";" _deps "${_deps_str}")

    # Filter to only existing targets (skip deps that weren't generated)
    set(_valid_deps "")
    foreach(_dep IN LISTS _deps)
      if(TARGET ${_dep})
        list(APPEND _valid_deps ${_dep})
      endif()
    endforeach()

    if(_valid_deps)
      target_link_libraries(${_target} ${_visibility} ${_valid_deps})
    endif()
  endforeach()
endfunction()

# Create the monolithic fizz library from all component OBJECT libraries
# Call this after all add_subdirectory() calls, before fizz_resolve_deferred_dependencies()
function(fizz_create_monolithic_library)
  get_property(_component_targets GLOBAL PROPERTY FIZZ_COMPONENT_TARGETS)

  if(NOT _component_targets)
    message(STATUS "No component targets found, skipping monolithic library creation")
    return()
  endif()

  # Collect all object files from component targets
  set(_all_objects)
  foreach(_target IN LISTS _component_targets)
    list(APPEND _all_objects $<TARGET_OBJECTS:${_target}>)
  endforeach()

  # Create the monolithic library
  add_library(fizz ${_all_objects})

  if(BUILD_SHARED_LIBS)
    set_property(TARGET fizz PROPERTY POSITION_INDEPENDENT_CODE ON)
    set_property(TARGET fizz PROPERTY VERSION ${PACKAGE_VERSION})
  endif()

  target_include_directories(fizz
    PUBLIC
      $<BUILD_INTERFACE:${FIZZ_BASE_DIR}>
      $<BUILD_INTERFACE:${FIZZ_GENERATED_DIR}>
      $<INSTALL_INTERFACE:${INCLUDE_INSTALL_DIR}>
      ${FOLLY_INCLUDE_DIR}
      ${OPENSSL_INCLUDE_DIR}
      ${sodium_INCLUDE_DIR}
      ${ZSTD_INCLUDE_DIR}
    PRIVATE
      ${GLOG_INCLUDE_DIRS}
      ${FIZZ_INCLUDE_DIRECTORIES}
  )

  target_compile_features(fizz PUBLIC cxx_std_20)

  # Link all dependencies
  target_link_libraries(fizz
    PUBLIC
      Folly::folly
      ${OPENSSL_LIBRARIES}
      sodium
      Threads::Threads
      ZLIB::ZLIB
      ${ZSTD_LIBRARY}
    PRIVATE
      ${GLOG_LIBRARIES}
      ${GFLAGS_LIBRARIES}
      ${FIZZ_LINK_LIBRARIES}
      ${CMAKE_DL_LIBS}
      ${LIBRT_LIBRARIES}
  )

  if (liboqs_FOUND)
    target_link_libraries(fizz PRIVATE OQS::oqs)
  endif()

  if (aegis_FOUND)
    target_link_libraries(fizz PRIVATE aegis::aegis)
  endif()

  if ($FIZZ_SHINY_DEPENDENCIES)
    add_dependencies(fizz ${FIZZ_SHINY_DEPENDENCIES})
  endif()

  if (${CMAKE_CXX_COMPILER_ID} STREQUAL MSVC)
    target_compile_options(fizz PUBLIC /bigobj)
  endif()

  # Create alias for consistency
  add_library(fizz::fizz ALIAS fizz)

  # For shared builds: link all granular INTERFACE targets to the monolithic library
  if(BUILD_SHARED_LIBS)
    cmake_policy(SET CMP0079 NEW)
    get_property(_interface_targets GLOBAL PROPERTY FIZZ_GRANULAR_INTERFACE_TARGETS)
    foreach(_target IN LISTS _interface_targets)
      target_link_libraries(${_target} INTERFACE fizz)
    endforeach()
  endif()
endfunction()
