project(test_cmake_install)

find_package(UTP REQUIRED)
message("UTP_LIBRARIES:${UTP_LIBRARIES}")
message("UTP_INCLUDE_DIRS:${UTP_INCLUDE_DIRS}")
message("UTP_DEFINITIONS:${UTP_DEFINITIONS}")
message("UTP_VERSION_STRING:${UTP_VERSION_STRING}")
