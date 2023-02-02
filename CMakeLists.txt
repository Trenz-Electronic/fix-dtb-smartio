cmake_minimum_required(VERSION 3.0)
project(fix-dtb-smartio CXX)
set(PACKAGE_AUTHOR "Andrei Errapart")


# Data for packaging.
set(CPACK_PACKAGE_VERSION_MAJOR 1)
set(CPACK_PACKAGE_VERSION_MINOR 0)
set(CPACK_PACKAGE_VERSION_PATCH 0)
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Fix dtb for use with smartio"
    CACHE STRING "Fix the device tree in image.ub such that the smartio entries appear in the decreasing memory buffer size"
)
set(CPACK_PACKAGE_VENDOR "Trenz Electronic GmbH")
set(CPACK_PACKAGE_CONTACT "a.errapart@trenz-electronic.de")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Andrei Errapart <${CPACK_PACKAGE_CONTACT}>")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_RESOURCE_FILE_README "${CMAKE_CURRENT_SOURCE_DIR}/README.md")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libcrypto++8")
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT) # otherwise we will get _Linux.deb file and not _amd64.deb.
set(CPACK_STRIP_FILES YES)
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS YES)


# Requirements
find_package(PkgConfig) # for the pkg_check_modules to work
pkg_check_modules(CRYPTOXX REQUIRED "libcrypto++")
if(NOT CRYPTOXX_FOUND)
    message(FATAL_ERROR "libcrypto++ required, but not found")
endif()

# fix-dtb-smartio
add_executable(fix-dtb-smartio dtc/dtc.c src/FixDtbSmartio.cpp)
target_link_libraries(fix-dtb-smartio ${CRYPTOXX_LIBRARIES})
target_compile_options(fix-dtb-smartio PUBLIC -I${CMAKE_CURRENT_SOURCE_DIR}/dtc/libfdt)
install(TARGETS fix-dtb-smartio RUNTIME DESTINATION bin)

# Debian package
include(CPack)

