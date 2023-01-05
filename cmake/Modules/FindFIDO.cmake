# - Try to find FIDO
# Once done this will define
#
#  FIDO_FOUND - system has FIDO
#  FIDO_INCLUDE_DIRS - the FIDO include directory
#  FIDO_LIBRARIES - Link these to use FIDO
#  FIDO_DEFINITIONS - Compiler switches required for using FIDO
#
#  Copyright (c) 2010 Andreas Schneider <asn@cryptomilk.org>
#  Copyright (c) 2013 Aris Adamantiadis <aris@badcode.be>
#
#  Redistribution and use is allowed according to the terms of the New
#  BSD license.
#  For details see the accompanying COPYING-CMAKE-SCRIPTS file.
#


if (FIDO_LIBRARIES AND FIDO_INCLUDE_DIRS)
  # in cache already
  set(FIDO_FOUND TRUE)
else (FIDO_LIBRARIES AND FIDO_INCLUDE_DIRS)
  find_path(FIDO_INCLUDE_DIR
    NAMES
      fido/credman.h
      fido.h
    PATHS
      /usr/include
      /usr/include/fido
  )

  find_library(FIDO_LIBRARY
    NAMES
      libfido2.so
      libfido2.pc
    PATHS
      /usr/lib/x86_64-linux-gnu/
      /usr/lib/x86_64-linux-gnu/pkgconfig/
  )

  set(FIDO_INCLUDE_DIRS
    ${FIDO_INCLUDE_DIR}
  )

  if (FIDO_LIBRARY)
    set(FIDO_LIBRARIES
        ${FIDO_LIBRARIES}
        ${FIDO_LIBRARY}
    )
  endif (FIDO_LIBRARY)

  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(FIDO DEFAULT_MSG FIDO_LIBRARIES FIDO_INCLUDE_DIRS)

  # show the FIDO_INCLUDE_DIRS and FIDO_LIBRARIES variables only in the advanced view
  mark_as_advanced(FIDO_INCLUDE_DIRS FIDO_LIBRARIES)

endif (FIDO_LIBRARIES AND FIDO_INCLUDE_DIRS)

