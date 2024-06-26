AC_INIT([sap], [0.1], [linus.luessing@c0d3.blue], [sap], [https://github.com/T-X/libsap])
AC_PREREQ([2.68])
AC_CONFIG_SRCDIR([src/libsap.c])
#AC_CONFIG_HEADERS([src/sap.h])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])


AC_ARG_WITH([zlib],
  [AS_HELP_STRING([--with-zlib],
    [use zlib for SAP compression @<:@default=check@:>@])],
  [],
  [with_zlib=check])

LIBZ=
AS_IF([test "x$with_zlib" != xno],
  [AC_CHECK_HEADERS([zlib.h],
    [AC_CHECK_LIB([z], [deflate],
      [AC_SUBST([LIBZ], ["-lz"])
       AC_DEFINE([HAVE_ZLIB], [1],
                 [Define if you have zlib])
      ],
      [if test "x$with_zlib" != xcheck; then
         AC_MSG_FAILURE(
           [--with-zlib was given, but test for zlib failed])
       fi
      ], )
    ])
  ])

AC_ARG_WITH([json-c],
  [AS_HELP_STRING([--with-json-c],
    [use json-c for JSON formatted status functions @<:@default=check@:>@])],
  [],
  [with_json_c=check])

JSONC=
AS_IF([test "x$with_json_c" != xno],
  [AC_CHECK_HEADERS([json-c/json.h],
    [AC_CHECK_LIB([json-c], [json_object_new_object],
      [AC_SUBST([JSONC], ["-ljson-c"])
       AC_DEFINE([HAVE_JSON_C], [1],
                 [Define if you have json-c])
      ],
      [if test "x$with_json-c" != xcheck; then
         AC_MSG_FAILURE(
           [--with-json-c was given, but test for json-c failed])
       fi
      ], )
    ])
  ])

AC_ARG_WITH([blake2],
  [AS_HELP_STRING([--with-blake2],
    [use blake2 for a deterministic SAP Message ID Hash @<:@default=check@:>@])],
  [],
  [with_blake2=check])

BLAKE2=
AS_IF([test "x$with_blake2" != xno],
  [AC_CHECK_HEADERS([blake2.h],
    [AC_CHECK_LIB([b2], [blake2b_init],
      [AC_SUBST([BLAKE2], ["-lb2"])
       AC_DEFINE([HAVE_BLAKE2], [1],
                 [Define if you have blake2])
      ],
      [if test "x$with_blake2" != xcheck; then
         AC_MSG_FAILURE(
           [--with-blake2 was given, but test for blake2 failed])
       fi
      ], )
    ])
  ])

AM_INIT_AUTOMAKE([1.11 subdir-objects -Wall -Werror])
AM_PROG_AR
LT_INIT
AC_CONFIG_FILES([Makefile])
AC_PROG_CC
AC_OUTPUT
