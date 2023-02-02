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
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Andrei Errapart")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_RESOURCE_FILE_README "${CMAKE_CURRENT_SOURCE_DIR}/README.md")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libcrypto++8")


find_package(PkgConfig)
find_package(Threads)
# TODO: check for libcrypto++

# fix-dtb-smartio
add_executable(fix-dtb-smartio dtc/dtc.c FixDtbSmartio/FixDtbSmartio.cpp)
target_link_libraries(fix-dtb-smartio crypto++)
target_compile_options(fix-dtb-smartio PUBLIC -I${CMAKE_CURRENT_SOURCE_DIR}/dtc/libfdt)
install(TARGETS fix-dtb-smartio RUNTIME DESTINATION bin)


# Debian package
include(CPack)

