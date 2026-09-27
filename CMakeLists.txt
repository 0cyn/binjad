cmake_minimum_required(VERSION 3.24)

if(APPLE AND NOT CMAKE_OSX_DEPLOYMENT_TARGET)
    set(CMAKE_OSX_DEPLOYMENT_TARGET "14.0" CACHE STRING "Minimum macOS version")
endif()

project(binjad VERSION 0.1.0 LANGUAGES C CXX)

if(APPLE)
    enable_language(OBJCXX)
    set(BINJAD_SERVICE_EXECUTABLE "" CACHE FILEPATH
        "Stable executable path embedded in the Homebrew LaunchAgent")
endif()

include(GNUInstallDirs)
list(PREPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build vendored dependencies as static libraries" FORCE)

if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/vendor/argon2/include/argon2.h")
    message(FATAL_ERROR
        "argon2 is missing. Initialize submodules with: "
        "git submodule update --init --recursive")
endif()
add_library(binjad_argon2 STATIC
    vendor/argon2/src/argon2.c
    vendor/argon2/src/core.c
    vendor/argon2/src/blake2/blake2b.c
    vendor/argon2/src/encoding.c
    vendor/argon2/src/ref.c)
target_include_directories(binjad_argon2
    PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/vendor/argon2/include"
    PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/vendor/argon2/src")
target_compile_definitions(binjad_argon2 PRIVATE ARGON2_NO_THREADS)
set_target_properties(binjad_argon2 PROPERTIES POSITION_INDEPENDENT_CODE ON)

set(BINJAD_BN_API_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/vendor/binaryninja-api")
if(NOT EXISTS "${BINJAD_BN_API_SOURCE_DIR}/binaryninjaapi.h")
    message(FATAL_ERROR
        "binaryninja-api is missing. Initialize submodules with: "
        "git submodule update --init --recursive")
endif()

include(VerifyBinaryNinjaRevision)
binjad_read_api_revision("${BINJAD_BN_API_SOURCE_DIR}" BINJAD_BN_API_REVISION)

set(BINJAD_DEBUGGER_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/vendor/debugger")
set(BINJAD_DEBUGGER_REVISION "bc5462f29a3389aefc807f89887f8767d9958a61")
if(NOT EXISTS "${BINJAD_DEBUGGER_SOURCE_DIR}/api/ffi.h")
    message(FATAL_ERROR
        "Vector35 Debugger is missing. Initialize submodules with: "
        "git submodule update --init --recursive")
endif()
binjad_read_api_revision("${BINJAD_DEBUGGER_SOURCE_DIR}" BINJAD_ACTUAL_DEBUGGER_REVISION)
if(NOT BINJAD_ACTUAL_DEBUGGER_REVISION STREQUAL BINJAD_DEBUGGER_REVISION)
    message(FATAL_ERROR
        "Vector35 Debugger revision mismatch: expected ${BINJAD_DEBUGGER_REVISION}, "
        "found ${BINJAD_ACTUAL_DEBUGGER_REVISION}")
endif()

set(BN_INSTALL_DIR "${BN_INSTALL_DIR}" CACHE PATH "Binary Ninja installation root")
if(NOT BN_INSTALL_DIR AND DEFINED ENV{BN_INSTALL_DIR} AND NOT "$ENV{BN_INSTALL_DIR}" STREQUAL "")
    set(BN_INSTALL_DIR "$ENV{BN_INSTALL_DIR}" CACHE PATH "Binary Ninja installation root" FORCE)
endif()

if(BN_INSTALL_DIR)
    binjad_verify_installed_api_revision("${BN_INSTALL_DIR}" "${BINJAD_BN_API_REVISION}")
    set(BN_ALLOW_STUBS OFF CACHE BOOL "Allow Binary Ninja core link stubs" FORCE)
else()
    message(STATUS "BN_INSTALL_DIR is unset; using the non-runtime Binary Ninja core link stub")
    set(BN_ALLOW_STUBS ON CACHE BOOL "Allow Binary Ninja core link stubs" FORCE)
endif()

set(HEADLESS ON CACHE BOOL "Build Binary Ninja API without UI support" FORCE)
set(BN_API_BUILD_EXAMPLES OFF CACHE BOOL "Build Binary Ninja API examples" FORCE)
add_subdirectory(vendor/binaryninja-api _deps/binaryninja-api EXCLUDE_FROM_ALL)

# Drogon requires JsonCpp. Reuse the implementation already compiled into the
# exact Binary Ninja API revision to avoid two JsonCpp ABIs in one executable.
set(BINJAD_JSONCPP_INCLUDE_DIR "${BINJAD_BN_API_SOURCE_DIR}")
set(BINJAD_JSONCPP_COMPAT_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include/binjad/compat")

set(BINJAD_ZLIB_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/vendor/zlib")
add_library(binjad_zlib STATIC
    vendor/zlib/adler32.c
    vendor/zlib/compress.c
    vendor/zlib/crc32.c
    vendor/zlib/deflate.c
    vendor/zlib/gzclose.c
    vendor/zlib/gzlib.c
    vendor/zlib/gzread.c
    vendor/zlib/gzwrite.c
    vendor/zlib/infback.c
    vendor/zlib/inffast.c
    vendor/zlib/inflate.c
    vendor/zlib/inftrees.c
    vendor/zlib/trees.c
    vendor/zlib/uncompr.c
    vendor/zlib/zutil.c)
target_include_directories(binjad_zlib PUBLIC "${BINJAD_ZLIB_SOURCE_DIR}")
set_target_properties(binjad_zlib PROPERTIES OUTPUT_NAME z POSITION_INDEPENDENT_CODE ON)
if(UNIX)
    target_compile_definitions(binjad_zlib PRIVATE HAVE_UNISTD_H)
endif()

set(BUILD_TESTING OFF CACHE BOOL "Build third-party tests" FORCE)
set(ABSL_ENABLE_INSTALL OFF CACHE BOOL "Do not install vendored Abseil" FORCE)
set(ABSL_BUILD_TESTING OFF CACHE BOOL "Build Abseil tests" FORCE)
set(ABSL_PROPAGATE_CXX_STD ON CACHE BOOL "Propagate the selected C++ standard" FORCE)
add_subdirectory(vendor/abseil-cpp _deps/abseil-cpp EXCLUDE_FROM_ALL)

set(protobuf_INSTALL OFF CACHE BOOL "Do not install vendored Protobuf" FORCE)
set(protobuf_BUILD_TESTS OFF CACHE BOOL "Build Protobuf tests" FORCE)
set(protobuf_BUILD_CONFORMANCE OFF CACHE BOOL "Build Protobuf conformance tests" FORCE)
set(protobuf_BUILD_EXAMPLES OFF CACHE BOOL "Build Protobuf examples" FORCE)
set(protobuf_BUILD_SHARED_LIBS OFF CACHE BOOL "Build Protobuf shared libraries" FORCE)
set(protobuf_LOCAL_DEPENDENCIES_ONLY ON CACHE BOOL "Do not download Protobuf dependencies" FORCE)
set(protobuf_WITH_ZLIB OFF CACHE BOOL "Build Protobuf zlib support" FORCE)
add_subdirectory(vendor/protobuf _deps/protobuf EXCLUDE_FROM_ALL)
include(vendor/protobuf/cmake/protobuf-generate.cmake)

set(BINJAD_PROTO_OUTPUT_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated/proto")
file(MAKE_DIRECTORY "${BINJAD_PROTO_OUTPUT_DIR}")
add_library(binjad_ipc_proto STATIC proto/ipc.proto)
protobuf_generate(
    TARGET binjad_ipc_proto
    LANGUAGE cpp
    APPEND_PATH
    PROTOC_OUT_DIR "${BINJAD_PROTO_OUTPUT_DIR}")
target_include_directories(binjad_ipc_proto PUBLIC "${BINJAD_PROTO_OUTPUT_DIR}")
target_link_libraries(binjad_ipc_proto PUBLIC protobuf::libprotobuf)
target_compile_features(binjad_ipc_proto PUBLIC cxx_std_20)

set(BUILD_CTL OFF CACHE BOOL "Build drogon_ctl" FORCE)
set(BUILD_EXAMPLES OFF CACHE BOOL "Build Drogon examples" FORCE)
set(BUILD_ORM OFF CACHE BOOL "Build Drogon ORM and database clients" FORCE)
set(BUILD_BROTLI OFF CACHE BOOL "Build Drogon Brotli support" FORCE)
set(BUILD_YAML_CONFIG OFF CACHE BOOL "Build Drogon YAML configuration support" FORCE)
set(BUILD_C-ARES OFF CACHE BOOL "Build Trantor c-ares support" FORCE)
set(TRANTOR_USE_TLS "none" CACHE STRING "Trantor TLS provider" FORCE)
set(USE_SUBMODULE ON CACHE BOOL "Use Drogon's pinned Trantor submodule" FORCE)
add_subdirectory(vendor/drogon _deps/drogon EXCLUDE_FROM_ALL)
if(TARGET trantor AND CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    target_compile_options(trantor PRIVATE -Wno-unused-result)
endif()

file(REMOVE
    "${CMAKE_CURRENT_BINARY_DIR}/generated/include/binjad/version.hpp"
    "${CMAKE_CURRENT_BINARY_DIR}/generated/include/binjad/reference/friendly_words_data.hpp")
configure_file(
    include/binjad/Version.hpp.in
    "${CMAKE_CURRENT_BINARY_DIR}/generated/include/binjad/Version.hpp"
    @ONLY)
file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/generated/include/binjad/reference")
file(SHA256 "${CMAKE_CURRENT_SOURCE_DIR}/resources/friendly_words.txt" BINJAD_FRIENDLY_WORDS_SHA256)
if(NOT BINJAD_FRIENDLY_WORDS_SHA256 STREQUAL
    "b8fb5eb1985737a49595a001c2871060b49e5c91755f7f76b4711ffe8ad1eb2f")
    message(FATAL_ERROR "resources/friendly_words.txt does not match the reviewed generated artifact")
endif()
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/resources/friendly_words.txt" BINJAD_FRIENDLY_WORDS)
list(LENGTH BINJAD_FRIENDLY_WORDS BINJAD_FRIENDLY_WORD_COUNT)
if(NOT BINJAD_FRIENDLY_WORD_COUNT EQUAL 16384)
    message(FATAL_ERROR "resources/friendly_words.txt must contain exactly 16384 words")
endif()
set(BINJAD_FRIENDLY_WORDS_HEADER
    "${CMAKE_CURRENT_BINARY_DIR}/generated/include/binjad/reference/FriendlyWordsData.hpp")
file(WRITE "${BINJAD_FRIENDLY_WORDS_HEADER}"
    "#pragma once\n\n#include <array>\n#include <string_view>\n\n"
    "namespace binjad::reference::detail\n{\n"
    "inline constexpr std::array<std::string_view, 16384> kFriendlyWords{{\n")
foreach(BINJAD_FRIENDLY_WORD IN LISTS BINJAD_FRIENDLY_WORDS)
    file(APPEND "${BINJAD_FRIENDLY_WORDS_HEADER}" "    \"${BINJAD_FRIENDLY_WORD}\",\n")
endforeach()
file(APPEND "${BINJAD_FRIENDLY_WORDS_HEADER}" "}};\n}\n")

if(APPLE)
    set(BINJAD_PLATFORM_PATH_SOURCE
        src/Shared/platform/macos/Logging.cpp
        src/Daemon/platform/macos/ControlUi.cpp
        src/Daemon/platform/macos/Cpu.cpp
        src/Daemon/platform/macos/Paths.cpp
        src/Shared/platform/posix/PrivateFiles.cpp)
    set(BINJAD_PLATFORM_SECURITY_SOURCES
        src/Daemon/platform/macos/CredentialStore.cpp
        src/Daemon/platform/macos/ToolControl.cpp
        src/Daemon/platform/macos/Random.cpp)
elseif(WIN32)
    set(BINJAD_PLATFORM_PATH_SOURCE
        src/Shared/platform/unsupported/Logging.cpp
        src/Daemon/platform/windows/Cpu.cpp
        src/Shared/platform/windows/Paths.cpp)
    set(BINJAD_PLATFORM_SECURITY_SOURCES
        src/Daemon/platform/unsupported/CredentialStore.cpp
        src/Daemon/platform/windows/Random.cpp)
elseif(UNIX)
    set(BINJAD_PLATFORM_PATH_SOURCE
        src/Shared/platform/unsupported/Logging.cpp
        src/Daemon/platform/linux/Cpu.cpp
        src/Daemon/platform/linux/Paths.cpp
        src/Shared/platform/posix/PrivateFiles.cpp)
    set(BINJAD_PLATFORM_SECURITY_SOURCES
        src/Daemon/platform/unsupported/CredentialStore.cpp
        src/Daemon/platform/linux/Random.cpp)
else()
    message(FATAL_ERROR "binjad has no user-data path adapter for this platform")
endif()

add_library(binjad_foundation STATIC
    src/Daemon/Config.cpp
    src/Daemon/mcp/Protocol.cpp
    ${BINJAD_PLATFORM_PATH_SOURCE})
target_include_directories(binjad_foundation
    PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include"
    PRIVATE "${BINJAD_BN_API_SOURCE_DIR}")
target_compile_features(binjad_foundation PUBLIC cxx_std_20)
if(APPLE)
    target_compile_definitions(binjad_foundation PRIVATE
        BINJAD_SERVICE_EXECUTABLE="${BINJAD_SERVICE_EXECUTABLE}")
endif()

add_library(binjad_security STATIC
    src/Daemon/security/Authentication.cpp
    src/Daemon/security/CredentialStore.cpp
    src/Daemon/security/Crypto.cpp
    src/Daemon/FriendlyReference.cpp
    src/Daemon/portal/Service.cpp
    src/Daemon/portal/Api.cpp
    src/Daemon/LocalProjectRegistry.cpp
    src/Daemon/session/AnalysisSessionRegistry.cpp
    src/Daemon/session/JobRegistry.cpp
    src/Daemon/session/OpenItemRegistry.cpp
    src/Daemon/session/SubscriptionRegistry.cpp
    src/Daemon/UploadRegistry.cpp
    ${BINJAD_PLATFORM_SECURITY_SOURCES})
target_include_directories(binjad_security
    PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
        "${CMAKE_CURRENT_BINARY_DIR}/generated/include"
    PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/src/Daemon/security"
        "${BINJAD_BN_API_SOURCE_DIR}")
target_compile_definitions(binjad_security PRIVATE
    BINJAD_PORTAL_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/resources/portal"
    BINJAD_PORTAL_INSTALL_DIR="${CMAKE_INSTALL_FULL_DATADIR}/binjad/portal")
target_link_libraries(binjad_security PUBLIC binjad_foundation trantor PRIVATE binjad_argon2)
target_compile_features(binjad_security PUBLIC cxx_std_20)
if(APPLE)
    find_library(BINJAD_SECURITY_FRAMEWORK Security REQUIRED)
    target_link_libraries(binjad_security PRIVATE "${BINJAD_SECURITY_FRAMEWORK}")
endif()

add_library(binjad_http STATIC
    src/Daemon/http/DrogonRoutes.cpp
    src/Daemon/http/McpAdmission.cpp
    src/Daemon/http/McpDispatcher.cpp
    src/Daemon/http/PortalRoutes.cpp
    src/Daemon/http/UploadRoutes.cpp
    src/Daemon/mcp/Foundation.cpp
    src/Daemon/mcp/ToolCall.cpp
    src/Daemon/mcp/tools/Analysis.cpp
    src/Daemon/mcp/tools/Broker.cpp
    src/Daemon/mcp/tools/Diffing.cpp
    src/Daemon/mcp/tools/HeaderParsing.cpp
    src/Daemon/mcp/tools/KernelCache.cpp
    src/Daemon/mcp/tools/Projects.cpp
    src/Daemon/mcp/tools/SharedCache.cpp
    src/Daemon/mcp/tools/UrlGeneration.cpp)
target_include_directories(binjad_http PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(binjad_http
    PUBLIC binjad_security Drogon::Drogon
    PRIVATE binaryninjaapi)
target_compile_features(binjad_http PUBLIC cxx_std_20)
if(WIN32)
    target_link_libraries(binjad_security PRIVATE bcrypt)
endif()

add_library(binjad_runtime STATIC
    src/Shared/Envelope.cpp
    src/Shared/Role.cpp)
if(APPLE)
    find_program(BINJAD_MIG_EXECUTABLE mig REQUIRED)
    execute_process(
        COMMAND xcrun --show-sdk-path
        RESULT_VARIABLE BINJAD_SDK_RESULT
        OUTPUT_VARIABLE BINJAD_MACOS_SDK
        OUTPUT_STRIP_TRAILING_WHITESPACE)
    if(NOT BINJAD_SDK_RESULT EQUAL 0)
        message(FATAL_ERROR "Unable to locate the macOS SDK for Mach exception definitions")
    endif()
    set(BINJAD_MIG_OUTPUT_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated/mig")
    file(MAKE_DIRECTORY "${BINJAD_MIG_OUTPUT_DIR}")
    set(BINJAD_MACH_EXC_SERVER_C "${BINJAD_MIG_OUTPUT_DIR}/mach_excServer.c")
    set(BINJAD_MACH_EXC_SERVER_H "${BINJAD_MIG_OUTPUT_DIR}/mach_excServer.h")
    add_custom_command(
        OUTPUT "${BINJAD_MACH_EXC_SERVER_C}" "${BINJAD_MACH_EXC_SERVER_H}"
        COMMAND "${BINJAD_MIG_EXECUTABLE}"
            -header /dev/null
            -user /dev/null
            -sheader "${BINJAD_MACH_EXC_SERVER_H}"
            -server "${BINJAD_MACH_EXC_SERVER_C}"
            "${BINJAD_MACOS_SDK}/usr/include/mach/mach_exc.defs"
        DEPENDS "${BINJAD_MACOS_SDK}/usr/include/mach/mach_exc.defs"
        VERBATIM)

    target_sources(binjad_runtime PRIVATE
        src/Shared/platform/macos/MachBootstrap.cpp
        src/Shared/platform/macos/MachChannel.cpp
        src/Daemon/platform/macos/ProcessSupervisor.cpp
        "${BINJAD_MACH_EXC_SERVER_C}")
    target_include_directories(binjad_runtime PRIVATE "${BINJAD_MIG_OUTPUT_DIR}")
    find_library(BINJAD_BSM_LIBRARY bsm REQUIRED)
    target_link_libraries(binjad_runtime PRIVATE "${BINJAD_BSM_LIBRARY}")
endif()
target_include_directories(binjad_runtime PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(binjad_runtime PUBLIC binjad_ipc_proto)
target_compile_features(binjad_runtime PUBLIC cxx_std_20)

add_library(binjad_binaryninja STATIC
    src/FileProcess/binary_ninja/Language.cpp
    src/FileProcess/binary_ninja/DiffTools.cpp
    src/Shared/Runtime.cpp
    src/FileProcess/binary_ninja/StringCodec.cpp
    vendor/binaryninja-api/view/kernelcache/api/kernelcache.cpp
    vendor/binaryninja-api/view/sharedcache/api/sharedcache.cpp
    vendor/debugger/api/debugadaptertype.cpp
    vendor/debugger/api/debuggercontroller.cpp
    src/FileProcess/ToolCall.cpp
    src/FileProcess/ToolSupport.cpp
    src/FileProcess/FileChild.cpp
    src/FileProcess/tools/Analysis.cpp
    src/FileProcess/tools/AnalysisMutations.cpp
    src/FileProcess/tools/Diffing.cpp
    src/FileProcess/tools/HeaderParsing.cpp
    src/FileProcess/tools/KernelCache.cpp
    src/FileProcess/tools/SharedCache.cpp
    src/FileProcess/tools/Debugger.cpp
    src/ProjectProcess/ProjectChild.cpp)
target_include_directories(binjad_binaryninja
    PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include"
    PRIVATE
        "${BINJAD_BN_API_SOURCE_DIR}/view/kernelcache/api"
        "${BINJAD_BN_API_SOURCE_DIR}/view/sharedcache/api"
        "${CMAKE_CURRENT_SOURCE_DIR}/vendor/debugger/api")
target_link_libraries(binjad_binaryninja PUBLIC binjad_runtime binaryninjaapi PRIVATE binjad_foundation)
target_compile_features(binjad_binaryninja PUBLIC cxx_std_20)

if(BN_INSTALL_DIR)
    if(APPLE)
        set(BINJAD_BN_PLUGIN_DIR "${BN_INSTALL_DIR}/Contents/MacOS/plugins")
    else()
        set(BINJAD_BN_PLUGIN_DIR "${BN_INSTALL_DIR}/plugins")
    endif()
    find_library(BINJAD_KERNELCACHE_LIBRARY NAMES kernelcache
        PATHS "${BINJAD_BN_PLUGIN_DIR}" NO_DEFAULT_PATH REQUIRED)
    find_library(BINJAD_SHAREDCACHE_LIBRARY NAMES sharedcache
        PATHS "${BINJAD_BN_PLUGIN_DIR}" NO_DEFAULT_PATH REQUIRED)
    find_library(BINJAD_DEBUGGERCORE_LIBRARY NAMES debuggercore
        PATHS "${BINJAD_BN_PLUGIN_DIR}" NO_DEFAULT_PATH REQUIRED)
else()
    find_package(Python3 COMPONENTS Interpreter REQUIRED)
    function(binjad_add_plugin_api_stub target output_name header api_macro library_macro include_dir)
        set(output "${CMAKE_CURRENT_BINARY_DIR}/${target}/stubs.cpp")
        add_custom_command(
            OUTPUT "${output}"
            COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/cmake/GeneratePluginApiStubs.py"
                "${header}" "${api_macro}" "${output}"
            DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/cmake/GeneratePluginApiStubs.py" "${header}"
            VERBATIM)
        add_library(${target} SHARED "${output}")
        target_include_directories(${target} PRIVATE
            "${BINJAD_BN_API_SOURCE_DIR}" "${include_dir}")
        target_compile_definitions(${target} PRIVATE "${library_macro}")
        set_target_properties(${target} PROPERTIES OUTPUT_NAME "${output_name}")
    endfunction()
    binjad_add_plugin_api_stub(binjad_kernelcache_stubs kernelcache
        "${BINJAD_BN_API_SOURCE_DIR}/view/kernelcache/api/kernelcachecore.h"
        KERNELCACHE_FFI_API KERNELCACHE_LIBRARY "${BINJAD_BN_API_SOURCE_DIR}/view/kernelcache/api")
    binjad_add_plugin_api_stub(binjad_sharedcache_stubs sharedcache
        "${BINJAD_BN_API_SOURCE_DIR}/view/sharedcache/api/sharedcachecore.h"
        SHAREDCACHE_FFI_API SHAREDCACHE_LIBRARY "${BINJAD_BN_API_SOURCE_DIR}/view/sharedcache/api")
    binjad_add_plugin_api_stub(binjad_debuggercore_stubs debuggercore
        "${BINJAD_DEBUGGER_SOURCE_DIR}/api/ffi.h"
        DEBUGGER_FFI_API DEBUGGER_LIBRARY "${BINJAD_DEBUGGER_SOURCE_DIR}/api")
    set(BINJAD_KERNELCACHE_LIBRARY binjad_kernelcache_stubs)
    set(BINJAD_SHAREDCACHE_LIBRARY binjad_sharedcache_stubs)
    set(BINJAD_DEBUGGERCORE_LIBRARY binjad_debuggercore_stubs)
endif()
target_link_libraries(binjad_binaryninja PRIVATE
    "${BINJAD_KERNELCACHE_LIBRARY}"
    "${BINJAD_SHAREDCACHE_LIBRARY}"
    "${BINJAD_DEBUGGERCORE_LIBRARY}")

add_library(binjad_overseer STATIC
    src/Daemon/overseer/AnalysisScheduler.cpp
    src/Daemon/overseer/FileChildCoordinator.cpp
    src/Daemon/overseer/ProjectChildCoordinator.cpp)
target_include_directories(binjad_overseer
    PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include"
    PRIVATE "${BINJAD_BN_API_SOURCE_DIR}")
target_link_libraries(binjad_overseer PUBLIC binjad_runtime binjad_security)
target_compile_features(binjad_overseer PUBLIC cxx_std_20)
target_link_libraries(binjad_http PUBLIC binjad_overseer)

add_executable(binjad src/Shared/Main.cpp)
target_include_directories(binjad PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    "${CMAKE_CURRENT_BINARY_DIR}/generated/include")
target_link_libraries(binjad PRIVATE
    binjad_http
    binjad_binaryninja
    binjad_overseer)
target_compile_features(binjad PRIVATE cxx_std_20)

if(APPLE)
    configure_file(packaging/macos/BinjadMenuBar-Info.plist.in
        "${CMAKE_CURRENT_BINARY_DIR}/BinjadMenuBar-Info.plist" @ONLY)
    set_source_files_properties(resources/menubar.png PROPERTIES
        MACOSX_PACKAGE_LOCATION Resources)
    add_executable(binjad-menubar MACOSX_BUNDLE
        src/MenuBar/MenuBar.mm
        resources/menubar.png)
    find_library(BINJAD_APPKIT_FRAMEWORK AppKit REQUIRED)
    target_link_libraries(binjad-menubar PRIVATE "${BINJAD_APPKIT_FRAMEWORK}")
    target_compile_features(binjad-menubar PRIVATE cxx_std_20)
    target_compile_options(binjad-menubar PRIVATE -fobjc-arc -Wall -Wextra -Wpedantic)
    set_target_properties(binjad-menubar PROPERTIES
        MACOSX_BUNDLE_INFO_PLIST "${CMAKE_CURRENT_BINARY_DIR}/BinjadMenuBar-Info.plist")
endif()

if(MSVC)
    target_compile_options(binjad_foundation PRIVATE /W4 /permissive-)
    target_compile_options(binjad_security PRIVATE /W4 /permissive-)
    target_compile_options(binjad_http PRIVATE /W4 /permissive-)
    target_compile_options(binjad_binaryninja PRIVATE /W4 /permissive-)
    target_compile_options(binjad_overseer PRIVATE /W4 /permissive-)
    target_compile_options(binjad PRIVATE /W4 /permissive-)
else()
    target_compile_options(binjad_foundation PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(binjad_security PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(binjad_http PRIVATE
        -Wall -Wextra -Wpedantic
        -Wno-gcc-compat
        -Wno-nullability-extension)
    target_compile_options(binjad_binaryninja PRIVATE
        -Wall -Wextra -Wpedantic
        -Wno-gcc-compat
        -Wno-ignored-qualifiers
        -Wno-nullability-extension
        -Wno-unused-parameter)
    target_compile_options(binjad_overseer PRIVATE
        -Wall -Wextra -Wpedantic
        -Wno-gcc-compat
        -Wno-nullability-extension)
    target_compile_options(binjad PRIVATE
        -Wall -Wextra -Wpedantic
        -Wno-gcc-compat
        -Wno-nullability-extension)
endif()

if(APPLE)
    if(BN_INSTALL_DIR)
        set(BINJAD_BN_CORE_RPATH "${BN_INSTALL_DIR}/Contents/MacOS")
    else()
        set(BINJAD_BN_CORE_RPATH "/Applications/Binary Ninja.app/Contents/MacOS")
    endif()
    set_target_properties(binjad PROPERTIES INSTALL_RPATH
        "${BINJAD_BN_CORE_RPATH};${BINJAD_BN_CORE_RPATH}/plugins")
endif()

install(TARGETS binjad RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
if(APPLE)
    install(TARGETS binjad-menubar BUNDLE DESTINATION "${CMAKE_INSTALL_LIBEXECDIR}")
    if(BINJAD_SERVICE_EXECUTABLE)
        configure_file(packaging/macos/me.cynder.binjad.plist.in
            "${CMAKE_CURRENT_BINARY_DIR}/me.cynder.binjad.plist" @ONLY)
        install(FILES "${CMAKE_CURRENT_BINARY_DIR}/me.cynder.binjad.plist"
            DESTINATION ".")
    endif()
endif()
install(FILES resources/SCOWL-LICENSE.txt
    DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/doc/binjad")
install(FILES vendor/debugger/LICENSE
    DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/doc/binjad"
    RENAME Debugger-LICENSE.txt)
install(DIRECTORY resources/portal/
    DESTINATION "${CMAKE_INSTALL_DATADIR}/binjad/portal")
install(CODE [[
    set(binjad_install_root "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}")
    file(GLOB_RECURSE binjad_installed_files LIST_DIRECTORIES FALSE
        "${binjad_install_root}/*")
    foreach(binjad_installed_file IN LISTS binjad_installed_files)
        get_filename_component(binjad_installed_name "${binjad_installed_file}" NAME)
        if(binjad_installed_name MATCHES
            "^(lib)?(binaryninjacore|kernelcache|sharedcache|debuggercore)(([.][0-9]+)*[.]dylib|[.]so([.][0-9]+)*|[.](dll|lib))$")
            message(FATAL_ERROR
                "Binary Ninja runtime library must not be installed or packaged: "
                "${binjad_installed_file}")
        endif()
    endforeach()
]])

option(BINJAD_BUILD_TESTS "Enable real-daemon end-to-end tests" ON)
if(BINJAD_BUILD_TESTS)
    enable_testing()
    if(APPLE)
        add_test(NAME binjad.menubar_bundle
            COMMAND "${CMAKE_COMMAND}"
                -DBINJAD_MENU_BAR_BUNDLE=$<TARGET_BUNDLE_DIR:binjad-menubar>
                -DBINJAD_MENU_BAR_ICON=${CMAKE_CURRENT_SOURCE_DIR}/resources/menubar.png
                -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/VerifyMenuBarBundle.cmake")
        set_tests_properties(binjad.menubar_bundle PROPERTIES LABELS "binjad;menubar")
    endif()
    if(BN_INSTALL_DIR AND APPLE)
        find_package(Python3 3.11 COMPONENTS Interpreter REQUIRED)
        find_program(BINJAD_E2E_CLANG NAMES clang REQUIRED)
        find_program(BINJAD_E2E_ELF_LINKER NAMES ld.lld REQUIRED)
        find_program(BINJAD_E2E_PE_LINKER NAMES lld-link REQUIRED)
        set(BINJAD_E2E_CORPUS "" CACHE FILEPATH "Optional local binary/cache corpus manifest")
        option(BINJAD_E2E_REQUIRE_CORPUS "Fail E2E runs without an external corpus" OFF)
        set(BINJAD_E2E_ARGUMENTS)
        if(BINJAD_E2E_CORPUS)
            list(APPEND BINJAD_E2E_ARGUMENTS --corpus "${BINJAD_E2E_CORPUS}")
        endif()
        if(BINJAD_E2E_REQUIRE_CORPUS)
            list(APPEND BINJAD_E2E_ARGUMENTS --require-corpus)
        endif()
        add_test(NAME binjad.e2e
            COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/e2e/Run.py"
                --daemon "$<TARGET_FILE:binjad>"
                --artifacts "${CMAKE_CURRENT_BINARY_DIR}/e2e"
                --clang "${BINJAD_E2E_CLANG}"
                --elf-linker "${BINJAD_E2E_ELF_LINKER}"
                --pe-linker "${BINJAD_E2E_PE_LINKER}"
                ${BINJAD_E2E_ARGUMENTS})
        set_tests_properties(binjad.e2e PROPERTIES
            LABELS "binjad;e2e"
            RESOURCE_LOCK binjad_mach_service
            TIMEOUT 3600)
    else()
        message(STATUS "Real-daemon E2E tests require BN_INSTALL_DIR and a supported service adapter (currently macOS)")
    endif()
endif()
