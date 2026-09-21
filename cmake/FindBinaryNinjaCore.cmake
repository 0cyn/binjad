if(NOT BN_INSTALL_DIR)
    set(BinaryNinjaCore_FOUND FALSE)
    set(BN_FOUND FALSE)
    return()
endif()

unset(BinaryNinjaCore_LIBRARY CACHE)
unset(BinaryNinjaCore_LIBRARY)

if(WIN32)
    set(binary_ninja_library_dir "${BN_INSTALL_DIR}")
elseif(APPLE)
    set(binary_ninja_library_dir "${BN_INSTALL_DIR}/Contents/MacOS")
else()
    set(binary_ninja_library_dir "${BN_INSTALL_DIR}")
endif()

find_library(BinaryNinjaCore_LIBRARY
    NAMES binaryninjacore libbinaryninjacore.so.1
    PATHS "${binary_ninja_library_dir}"
    NO_DEFAULT_PATH)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(BinaryNinjaCore
    REQUIRED_VARS BinaryNinjaCore_LIBRARY)

if(BinaryNinjaCore_FOUND)
    set(BinaryNinjaCore_ROOT_DIR "${BN_INSTALL_DIR}")
    set(BinaryNinjaCore_INCLUDE_DIRS "")
    set(BinaryNinjaCore_LIBRARIES "${BinaryNinjaCore_LIBRARY}")
    set(BinaryNinjaCore_LIBRARY_DIRS "${binary_ninja_library_dir}")
    set(BinaryNinjaCore_DEFINITIONS "")

    set(BN_FOUND TRUE)
    set(BN_INSTALL_BIN_DIR "${binary_ninja_library_dir}")
    set(BN_CORE_LIBRARY "${BinaryNinjaCore_LIBRARY}")
    set(BN_CORE_DEFINITIONS "")
endif()
