# Author: KangLin(kl222@126.com)

project(ucat)

unset(UTP_DEFINES)
unset(UTP_LIBS)

utp_check_include_file("strings.h" HAVE_STRING_H)
utp_check_include_file("unistd.h" HAVE_UNISTD_H)

if(WIN32)
	set(UTP_DEFINES ${UTP_DEFINES} WIN32 WINDOWS)
    utp_check_include_file("winsock2.h" HAVE_WINSOCK2_H)
	utp_check_library_exists(Ws2_32 ioctlsocket HAVE_WS2_32_LIB)
	utp_check_library_exists(Ws2_32 socket HAVE_WS2_32_LIB)
    SET(UTP_DEFINES ${UTP_DEFINES} HAVE_SELECT)
else(WIN32)
    check_include_file("sys/socket.h" HAVE_SOCKET_H)
    check_include_file("arpa/inet.h" HAVE_INET_H)
    check_include_file("netinet/in.h" HAVE_IN_H)
    utp_check_symbol_exists(select sys/socket.h HAVE_SELECT)
endif(WIN32)

message("LIBEVENT_SHARED_LIBRARIES:${LIBEVENT_SHARED_LIBRARIES}")

find_package(Libevent 2.0.10)
if(Libevent_FOUND)
	utp_check_symbol_exists(SIGINT signal.h HAVE_SIGNAL)
    message("Add path ${Libevent_DIR}/../lib to environmental variable PATH")
    set(UCAT_INCLUDES ${UCAT_INCLUDES} ${LIBEVENT_INCLUDE_DIRS})
    set(UTP_LIBS ${UTP_LIBS} ${LIBEVENT_SHARED_LIBRARIES})
	set(SOURCE_FILES
		${SOURCE_FILES}
	    ucat.cpp
		)
    if(WIN32)
        set(SOURCE_FILES
            ${SOURCE_FILES}
            Stdin.cpp
            Stdin.h)
    endif()
else()
	utp_check_symbol_exists(sigaction signal.h HAVE_SIGNAL)
	set(SOURCE_FILES ${SOURCE_FILES} ucat.c)
endif()

set(SOURCE_FILES
	${SOURCE_FILES}
	Buffer.cpp
	Buffer.h
	Socket.cpp
	Socket.h
	Log.cpp
	Log.h)
utp_check_function_exists(getopt HAVE_GETOPT)
if(NOT HAVE_GETOPT)
    set(SOURCE_FILES
        ${SOURCE_FILES}
        getopt.c
        getopt.h
        )
endif()

if (CMAKE_COMPILER_IS_GNUCXX)
    SET(UTP_DEFINES ${UTP_DEFINES} POSIX)
endif()

add_executable(ucat ${SOURCE_FILES})
target_link_libraries(ucat utp ${UTP_LIBS})
target_compile_definitions(${PROJECT_NAME} PRIVATE ${UTP_DEFINES})
target_include_directories(ucat PRIVATE
    ${CMAKE_BINARY_DIR}/src
    ${CMAKE_SOURCE_DIR}/src
    ${UCAT_INCLUDES})

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
