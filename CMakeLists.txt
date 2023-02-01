cmake_minimum_required(VERSION 3.0)
project(fix-dtb-smartio CXX)
set(PACKAGE_AUTHOR "Andrei Errapart")

# Set the version information here
set(MAJOR_VERSION 1)
set(LIBVER ${MAJOR_VERSION}.0.0)

find_package(PkgConfig)
find_package(Threads)

# fix-dtb-smartio
add_executable(fix-dtb-smartio dtc/dtc.c FixDtbSmartio/FixDtbSmartio.cpp)
target_link_libraries(fix-dtb-smartio crypto++)
target_compile_options(fix-dtb-smartio PUBLIC -I${CMAKE_CURRENT_SOURCE_DIR}/dtc/libfdt)
install(TARGETS fix-dtb-smartio RUNTIME DESTINATION bin)

