## This module will automagically download the tarball of the specified jsoncons version and create
## an INTERFACE target exposing the header-only library.
##
## Example usage:
##
##    # Find jsoncons
##    find_package(
##        Jsoncons 1.7.0
##        REQUIRED
##    )
##
##    # Link to the target
##    target_link_libraries(
##        MyTarget
##        PRIVATE
##            Jsoncons::Jsoncons
##    )
##

include(FetchContent)

# Assemble version string (jsoncons tags use a "v" prefix)
set(Jsoncons_VERSION_STRING ${Jsoncons_FIND_VERSION_MAJOR}.${Jsoncons_FIND_VERSION_MINOR}.${Jsoncons_FIND_VERSION_PATCH})

# Assemble download URL
set(DOWNLOAD_URL https://github.com/danielaparker/jsoncons/archive/refs/tags/v${Jsoncons_VERSION_STRING}.tar.gz)

# Optional Jsoncons PATH hinting
set(Jsoncons_PATH "" CACHE PATH "Path to jsoncons installation")

if(NOT Jsoncons_PATH)
    # Ensure that find_package() got a version specification
    if(NOT Jsoncons_FIND_VERSION)
        message(FATAL_ERROR "Cannot download jsoncons tarball without a version specified in find_package()")
    endif()

    # CMake 3.28: EXCLUDE_FROM_ALL prevents jsoncons build targets from polluting the ALL target
    FetchContent_Declare(
        jsoncons
        URL ${DOWNLOAD_URL}
        EXCLUDE_FROM_ALL
    )
    FetchContent_MakeAvailable(jsoncons)
else()
    # User suggested a path
    message(STATUS "Using user-suggested jsoncons path: ${Jsoncons_PATH}")

    if(NOT EXISTS ${Jsoncons_PATH}/include/jsoncons/json.hpp)
        message(FATAL_ERROR "jsoncons path hint found, but couldn't detect headers at: ${Jsoncons_PATH}/include/jsoncons/json.hpp")
    endif()

    # Heuristically detect the version from version.hpp
    set(JSONCONS_VERSION_HPP ${Jsoncons_PATH}/include/jsoncons/version.hpp)
    if(EXISTS ${JSONCONS_VERSION_HPP})
        file(READ ${JSONCONS_VERSION_HPP} JSONCONS_VERSION_FILE)
        string(REGEX MATCH "JSONCONS_VERSION_MAJOR[ \t]+([0-9]+)" _match "${JSONCONS_VERSION_FILE}")
        set(JSONCONS_VERSION_MAJOR ${CMAKE_MATCH_1})
        string(REGEX MATCH "JSONCONS_VERSION_MINOR[ \t]+([0-9]+)" _match "${JSONCONS_VERSION_FILE}")
        set(JSONCONS_VERSION_MINOR ${CMAKE_MATCH_1})
        string(REGEX MATCH "JSONCONS_VERSION_PATCH[ \t]+([0-9]+)" _match "${JSONCONS_VERSION_FILE}")
        set(JSONCONS_VERSION_PATCH ${CMAKE_MATCH_1})

        set(JSONCONS_REPOVERSION "${JSONCONS_VERSION_MAJOR}.${JSONCONS_VERSION_MINOR}.${JSONCONS_VERSION_PATCH}")

        # If user didn't provide a required version
        if(Jsoncons_VERSION_STRING STREQUAL "..")
            set(Jsoncons_VERSION_STRING ${JSONCONS_REPOVERSION})
        else()
            if(NOT JSONCONS_REPOVERSION STREQUAL Jsoncons_VERSION_STRING)
                message(FATAL_ERROR "jsoncons version hint (${Jsoncons_VERSION_STRING}) doesn't match the one found in the repository (${JSONCONS_REPOVERSION})")
            endif()
        endif()
    endif()

    FetchContent_Declare(
        jsoncons
        SOURCE_DIR ${Jsoncons_PATH}
        EXCLUDE_FROM_ALL
    )
    FetchContent_MakeAvailable(jsoncons)
endif()

# Heavy lifting by cmake
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Jsoncons DEFAULT_MSG Jsoncons_VERSION_STRING)

# jsoncons's own CMakeLists.txt defines the "jsoncons" INTERFACE target;
# create an alias using the conventional Namespace::Target naming.
if(TARGET jsoncons AND NOT TARGET Jsoncons::Jsoncons)
    add_library(Jsoncons::Jsoncons ALIAS jsoncons)
endif()
