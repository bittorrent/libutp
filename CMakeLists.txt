cmake_minimum_required(VERSION 3.0)

set (UTP_SOURCE_FILES
    utp_api.cpp
    utp_callbacks.cpp
    utp_hash.cpp
    utp_internal.cpp
    utp_packedsockaddr.cpp
    utp_utils.cpp
)

add_library(utp STATIC ${UTP_SOURCE_FILES})
