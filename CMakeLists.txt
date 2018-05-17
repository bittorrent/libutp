project(utp)
cmake_minimum_required(VERSION 2.8)

if (WIN32)
  set(PLATFORM_SOURCES libutp_inet_ntop.cpp)
  add_definitions(-D_WIN32_WINNT=0x501)
  # disable crt security warnings for now -- ideally the code should be fixed
  # to use the "safe" versions of the CRT functions on Windows.
  add_definitions(-D_CRT_SECURE_NO_WARNINGS)
  set(PLATFORM_LIBS ws2_32)
elseif(ANDROID)
  add_definitions(-DPOSIX)
elseif(UNIX)
  find_package(Threads)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -g -fno-exceptions")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC -fno-rtti")
  add_definitions(-DPOSIX)
  set(PLATFORM_LIBS ${CMAKE_THREAD_LIBRARY_INIT})
  if (NOT APPLE)
    set(PLATFORM_LIBS ${PLATFORM_LIBS} rt)
  endif()
else()
  message(FATAL_ERROR "platform is not supported yet")
endif()

string(TOLOWER "${CMAKE_BUILD_TYPE}" BUILD_TYPE)
if ("${BUILD_TYPE}" STREQUAL "debug")
  add_definitions(-D_DEBUG)
endif()

if (UTP_DEBUG_LOGGING)
  add_definitions(-D_UTP_DEBUG_LOGGING)
endif()

add_library(utp-objs OBJECT
  utp_api.cpp
  utp_callbacks.cpp
  utp_hash.cpp
  utp_internal.cpp
  utp_packedsockaddr.cpp
  utp_utils.cpp
  ${PLATFORM_SOURCES}
  )

############################################
# static lib
############################################
add_library(utp-static STATIC $<TARGET_OBJECTS:utp-objs>)
target_link_libraries(utp-static ${PLATFORM_LIBS})
set_target_properties(utp-static PROPERTIES OUTPUT_NAME "utp")
set_target_properties(utp-static PROPERTIES PREFIX "lib")

############################################
# shared lib
############################################
if (WIN32)
  add_library(utp SHARED $<TARGET_OBJECTS:utp-objs> utp.def)
else()
  add_library(utp SHARED $<TARGET_OBJECTS:utp-objs>)
endif()
target_link_libraries(utp ${PLATFORM_LIBS})

if (NOT ANDROID)
############################################
# installation
############################################
foreach(PLATFORM_LIB ${PLATFORM_LIBS})
  set(PLATFORM_LIBS_LINK ${PLATFORM_LIBS_LINK} -l${PLATFORM_LIB})
endforeach()
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/utp.pc.in
               ${CMAKE_CURRENT_BINARY_DIR}/utp.pc
               @ONLY)
INSTALL(FILES utp.h utp_types.h DESTINATION include)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/utp.pc DESTINATION lib/pkgconfig)
INSTALL(TARGETS utp-static utp
    RUNTIME DESTINATION bin LIBRARY DESTINATION lib ARCHIVE DESTINATION lib)

############################################
# ucat (non-windows platforms only)
############################################
if (NOT WIN32)
  add_library(ucat-objs OBJECT ucat.c)

  add_executable(ucat-static $<TARGET_OBJECTS:ucat-objs>)
  target_link_libraries(ucat-static utp-static)

  add_executable(ucat $<TARGET_OBJECTS:ucat-objs>)
  target_link_libraries(ucat utp)

  INSTALL(TARGETS ucat ucat-static
      RUNTIME DESTINATION bin LIBRARY DESTINATION lib ARCHIVE DESTINATION lib)
endif(NOT WIN32)

############################################
# Ctags
############################################

add_custom_target(tags
  ctags *.cpp *.h
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

endif(NOT ANDROID)
