# Author: KangLin(kl222@126.com)

project(utp)

check_include_file("stdlib.h" HAVE_STDLIB_H)
check_include_file("string.h" HAVE_STRING_H)
check_include_file("stdarg.h" HAVE_STDARG_H)
check_include_file("stdio.h" HAVE_STDIO_H)
check_include_file("assert.h" HAVE_ASSERT_H)
check_include_file("limits.h" HAVE_LIMITS_H)
check_include_file("time.h" HAVE_TIME_H)

if(WIN32)
    check_include_file("winsock2.h" HAVE_WINSOCK2_H)
    check_include_file("ws2tcpip.h" HAVE_WS2TCPIP_H)
    
    set(UTP_DEFINES ${UTP_DEFINES} WIN32)
    set(UTP_LIBS ${UTP_LIBS} Ws2_32)
    #utp_check_library_exists(Ws2_32 socket HAVE_WS2_32_LIB)
else(WIN32)
    check_include_file("sys/socket.h" HAVE_SOCKET_H)
    check_include_file("arpa/inet.h" HAVE_INET_H)
    check_include_file("netinet/in.h" HAVE_IN_H)
endif(WIN32)

check_function_exists(wprintf HAVE_WPRINTF)

if (CMAKE_COMPILER_IS_GNUCXX)
    set(UTP_DEFINES ${UTP_DEFINES} POSIX)
endif()

set(UTP_DEFINES ${UTP_DEFINES} _UNICODE UNICODE)

set(SOURCE_FILES
    utp_internal.cpp
    utp_utils.cpp
    utp_hash.cpp
    utp_callbacks.cpp
    utp_api.cpp
    utp_packedsockaddr.cpp
  )

set(INSTALL_HEAD_FILES
    utp_types.h
    utp.h
)
set(HEAD_FILES
    utp_hash.h
    utp_templates.h
    utp_internal.h
    utp_callbacks.h
    utp_packedsockaddr.h
    utp_utils.h
    ${INSTALL_HEAD_FILES}
  )

if(WIN32)
    SET(SOURCE_FILES ${SOURCE_FILES}
        libutp_inet_ntop.cpp)
    SET(HEAD_FILES ${HEAD_FILES} 
        libutp_inet_ntop.h)
endif(WIN32)

add_library(${PROJECT_NAME} ${SOURCE_FILES} ${HEAD_FILES})
target_link_libraries(${PROJECT_NAME} ${UTP_LIBS})
set_target_properties(${PROJECT_NAME} PROPERTIES SOVERSION ${VERSION_STRING})
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_compile_definitions(${PROJECT_NAME} PRIVATE ${UTP_DEFINES})

IF(NOT WIN32)
    target_compile_options(${PROJECT_NAME} PRIVATE -Wno-sign-compare -fpermissive -fno-rtti)
ENDIF()

if (BUILD_SHARED_LIBS)
    if (CMAKE_COMPILER_IS_GNUCXX)
       # Just setting CMAKE_POSITION_INDEPENDENT_CODE should be enough to set
       # -fPIC for GCC but sometimes it still doesn't get set, so make sure it
       # does.
       #add_compile_options("-fPIC")
       target_compile_options(${PROJECT_NAME} PRIVATE "-fPIC")
    endif()
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)   
endif()

include(GenerateExportHeader)
GENERATE_EXPORT_HEADER(${PROJECT_NAME})

# Install UTP library
install(TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    )
install(FILES
            ${INSTALL_HEAD_FILES}
            ${CMAKE_CURRENT_BINARY_DIR}/utp_export.h
        DESTINATION
            "${CMAKE_INSTALL_INCLUDEDIR}"
    )

export(TARGETS ${PROJECT_NAME}
  FILE "${CMAKE_BINARY_DIR}/UTPConfig.cmake")

foreach(_lib ${UTP_LIBS})
    set(PKGCONFIG_UTP_LIBS "${PKGCONFIG_UTP_LIBS} -l${_lib}")
    set(CMAKE_UTP_LIBS "${CMAKE_UTP_LIBS} ${_lib}")
endforeach()
foreach(d ${UTP_DEFINES})
    set(PKGCONFIG_UTP_DEFINES "${PKGCONFIG_UTP_DEFINES} -D${d}")
    set(CMAKE_UTP_DEFINES "${CMAKE_UTP_DEFINES} ${d}")
endforeach()
# PkgConfig configure file
if(NOT MSVC)
    configure_file(${CMAKE_SOURCE_DIR}/cmake/utp.pc.in
        ${CMAKE_CURRENT_BINARY_DIR}/utp.pc @ONLY)
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/utp.pc
            DESTINATION
                "${CMAKE_INSTALL_LIBDIR}/pkgconfig")
endif()

# Cmake configure files
include(CMakePackageConfigHelpers)
configure_package_config_file(${CMAKE_SOURCE_DIR}/cmake/UTPConfig.cmake.in
    "${CMAKE_CURRENT_BINARY_DIR}/UTPConfig.cmake"
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/CMake)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/UTPConfigVersion.cmake"
    VERSION ${VERSION_STRING}
    COMPATIBILITY AnyNewerVersion)
install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/UTPConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/UTPConfigVersion.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/CMake
  )

#*
# * Copyright (c) 2010-2013 BitTorrent, Inc.
# *
# * Permission is hereby granted, free of charge, to any person obtaining a copy
# * of this software and associated documentation files (the "Software"), to deal
# * in the Software without restriction, including without limitation the rights
# * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# * copies of the Software, and to permit persons to whom the Software is
# * furnished to do so, subject to the following conditions:
# *
# * The above copyright notice and this permission notice shall be included in
# * all copies or substantial portions of the Software.
# *
# * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# * THE SOFTWARE.
# *
