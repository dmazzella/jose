## This module will automagically download the tarball of the specified Botan version and invoke the configure.py
## python script to generate the amalgamation files (botan_all.cpp and botan_all.h).
##
## Example usage:
##
##    # Find Botan
##    find_package(
##        Botan 3.11.0
##        REQUIRED
##    )
##
##    # Create target "my_botan_target" with modules "system_rng" and "sha3" enabled
##    botan_generate(
##        my_botan_target
##            system_rng
##            sha3
##    )
##
##    # Link to generated target
##    target_link_libraries(
##        MyTarget
##        PRIVATE
##            my_botan_target
##    )
##

include(FetchContent)

# Policy for download timestamps
cmake_policy(SET CMP0135 NEW)

# Find python
find_package(
    Python
    COMPONENTS
        Interpreter
    REQUIRED
)

# Assemble version string
set(Botan_VERSION_STRING ${Botan_FIND_VERSION_MAJOR}.${Botan_FIND_VERSION_MINOR}.${Botan_FIND_VERSION_PATCH})

# Assemble download URL
set(DOWNLOAD_URL https://github.com/randombit/botan/archive/refs/tags/${Botan_VERSION_STRING}.tar.gz)

# Optional Botan PATH hinting
set(Botan_PATH "" CACHE PATH "Path to Botan installation")

if(NOT Botan_PATH)
    # Ensure that find_package() got a version specification
    if(NOT Botan_FIND_VERSION)
        message(FATAL_ERROR "Cannot download Botan tarball without a version specified in find_package()")
    endif()

    # CMake 3.30: explicit-parameter form of FetchContent_Populate is not deprecated
    # and never calls add_subdirectory, so Botan's own CMake build is never triggered.
    set(_botan_src_dir "${CMAKE_BINARY_DIR}/_deps/botan_upstream-src")
    if(NOT EXISTS "${_botan_src_dir}/configure.py")
        message(STATUS "Downloading Botan ${Botan_VERSION_STRING}...")
        FetchContent_Populate(
            botan_upstream
            QUIET
            SOURCE_DIR "${_botan_src_dir}"
            BINARY_DIR "${CMAKE_BINARY_DIR}/_deps/botan_upstream-build"
            URL ${DOWNLOAD_URL}
        )
    endif()
    set(botan_upstream_SOURCE_DIR "${_botan_src_dir}")
else()
    # User suggested a path
    message(STATUS "Using user-suggested Botan path: ${Botan_PATH}")
    set(botan_upstream_SOURCE_DIR ${Botan_PATH} CACHE INTERNAL "")

    if(NOT EXISTS ${botan_upstream_SOURCE_DIR}/configure.py)
        message(FATAL_ERROR "Botan path hint found, but couldn't detect the configure script at: ${botan_upstream_SOURCE_DIR}/configure.py")
    endif()

    # Heuristically detect the version from news.rst
    if(EXISTS ${botan_upstream_SOURCE_DIR}/news.rst)
        file(READ ${botan_upstream_SOURCE_DIR}/news.rst BOTAN_NEWSFILE)
        string(REGEX MATCH "[0-9]+\\.[0-9]+\\.[0-9]+" BOTAN_REPOVERSION "${BOTAN_NEWSFILE}")

        if(Botan_VERSION_STRING STREQUAL "..")
            set(Botan_VERSION_STRING ${BOTAN_REPOVERSION})
        else()
            if(NOT BOTAN_REPOVERSION STREQUAL Botan_VERSION_STRING)
                message(FATAL_ERROR "Botan version hint (${Botan_VERSION_STRING}) doesn't match the one found in the repository (${BOTAN_REPOVERSION})")
            endif()
        endif()
    endif()
endif()

# Heavy lifting by cmake
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Botan DEFAULT_MSG Botan_VERSION_STRING)

# Function to generate a static library target with specific Botan modules enabled.
# Usage: botan_generate(<target> <module> [<module> ...])
function(botan_generate TARGET_NAME)
    # ARGN holds all arguments after TARGET_NAME
    set(modules_list ${ARGN})

    if(NOT modules_list)
        message(FATAL_ERROR "botan_generate: at least one module must be specified")
    endif()

    # Check if PKCS11 module is enabled
    # Note: This is for a workaround, see further below for more details.
    if("pkcs11" IN_LIST modules_list)
        set(PKCS11_ENABLED ON)
    endif()

    list(JOIN modules_list "," ENABLE_MODULES_LIST)

    # Determine botan compiler ID (--cc parameter of configure.py)
    set(BOTAN_COMPILER_ID ${CMAKE_CXX_COMPILER_ID})
    string(TOLOWER ${BOTAN_COMPILER_ID} BOTAN_COMPILER_ID)
    if(BOTAN_COMPILER_ID STREQUAL "gnu")
        set(BOTAN_COMPILER_ID "gcc")
    elseif(BOTAN_COMPILER_ID STREQUAL "appleclang")
        set(BOTAN_COMPILER_ID "clang")
    endif()

    # Run the configure.py script.
    # Files are generated inside a "botan/" subdirectory so that consumers can
    # include them as <botan/botan_all.h>, matching the path expected by
    # jose/detail/botan_include.hpp.
    set(_botan_output_dir "${CMAKE_CURRENT_BINARY_DIR}/botan")
    file(MAKE_DIRECTORY "${_botan_output_dir}")

    add_custom_command(
        OUTPUT ${_botan_output_dir}/botan_all.cpp ${_botan_output_dir}/botan_all.h
        COMMENT "Generating Botan amalgamation files botan_all.cpp and botan_all.h"
        WORKING_DIRECTORY ${_botan_output_dir}
        COMMAND ${Python_EXECUTABLE}
            ${botan_upstream_SOURCE_DIR}/configure.py
            --quiet
            --cc-bin=${CMAKE_CXX_COMPILER}
            --cc=${BOTAN_COMPILER_ID}
            $<$<BOOL:${MINGW}>:--os=mingw>
            --disable-shared
            --amalgamation
            --minimized-build
            --enable-modules=${ENABLE_MODULES_LIST}
    )

    add_library(${TARGET_NAME} STATIC)
    target_compile_features(
        ${TARGET_NAME}
        PUBLIC
            cxx_std_20
    )
    target_sources(
        ${TARGET_NAME}
        PRIVATE
            ${_botan_output_dir}/botan_all.cpp
    )
    target_include_directories(
        ${TARGET_NAME}
        INTERFACE
            ${CMAKE_CURRENT_BINARY_DIR}
    )
    target_link_libraries(
        ${TARGET_NAME}
        PRIVATE
            $<$<NOT:$<BOOL:${MSVC}>>:pthread>
    )
    set_target_properties(
        ${TARGET_NAME}
        PROPERTIES
            POSITION_INDEPENDENT_CODE ON
    )

    #
    # PKCS11 Workaround
    #
    # This section is a workaround to handle a "bug" in upstream Botan.
    # Basically, the amalgamation build of Botan does not include the necessary PKCS11 headers when the PKCS11 module
    # is enabled.
    #
    # See:
    #   - https://github.com/randombit/botan/issues/1447
    #   - https://github.com/randombit/botan/issues/976
    #
    if(PKCS11_ENABLED)
        set(_pkcs11_dir "${botan_upstream_SOURCE_DIR}/src/lib/prov/pkcs11")
        foreach(_hdr pkcs11.h pkcs11f.h pkcs11t.h)
            if(EXISTS "${_pkcs11_dir}/${_hdr}")
                file(COPY "${_pkcs11_dir}/${_hdr}" DESTINATION ${_botan_output_dir})
            endif()
        endforeach()
        target_include_directories(
            ${TARGET_NAME}
            PRIVATE
                ${_pkcs11_dir}
        )
    endif()
endfunction()