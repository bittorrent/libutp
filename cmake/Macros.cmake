#File defines convenience macros for available feature testing

# This macro checks if the symbol exists in the library and if it
# does, it prepends library to the list.  It is intended to be called
# multiple times with a sequence of possibly dependent libraries in
# order of least-to-most-dependent.  Some libraries depend on others
# to link correctly.
macro(utp_check_library_exists LIBRARY SYMBOL VARIABLE)
  check_library_exists("${LIBRARY};${UTP_LIBS}" ${SYMBOL} "${CMAKE_LIBRARY_PATH}"
    ${VARIABLE})
  if(${VARIABLE})
    set(UTP_LIBS ${LIBRARY} ${UTP_LIBS})
  endif()
endmacro()

# Check if header file exists and add it to the list.
# This macro is intended to be called multiple times with a sequence of
# possibly dependent header files.  Some headers depend on others to be
# compiled correctly.
macro(utp_check_include_file FILE VARIABLE)
  check_include_files("${FILE}" ${VARIABLE})
  if(${VARIABLE})
    set(UTP_DEFINES ${UTP_DEFINES} ${VARIABLE})
  endif()
endmacro()

macro(utp_check_function_exists FUNCTION VARIABLE)
    check_function_exists(${FUNCTION} ${VARIABLE})
    if(${VARIABLE})
      set(UTP_DEFINES ${UTP_DEFINES} ${VARIABLE})
    endif()
endmacro()

macro(utp_check_symbol_exists SYMBOL FILE VARIABLE)
    check_symbol_exists(${SYMBOL} ${FILE} ${VARIABLE})
    if(${VARIABLE})
      set(UTP_DEFINES ${UTP_DEFINES} ${VARIABLE})
    endif()
endmacro()
