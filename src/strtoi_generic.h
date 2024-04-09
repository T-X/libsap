/* SPDX-FileCopyrightText: 2024 Linus Lüssing <linus.luessing@c0d3.blue> */
/* SPDX-License-Identifier: MIT */

/**
 * strtoi_(base_)generic() - convert a string to a generic integer
 *
 * The main goal of this is to provide more easy to use and safer versions
 * for string to integer conversions in C. With a cleaner separation of return
 * values and error codes, without errno. In contrast to strto*() functions
 * these two function-look-alikes/macros here need less surrounding
 * wrapping/checks than strto*() functions. A single return value check is
 * enough to verify correct parsing.
 *
 * Notably you can provide a pointer to any kind of integer type for result
 * storage - they will be able to check if the result would fit beforehand.
 *
 * Yes, you heard right, generics in C!
 *
 * Needs a modern C compiler for the C23 typeof() feature and the C11 _Generic()
 * feature.
 */

#ifndef __STRTOI_GENERIC_H__
#define __STRTOI_GENERIC_H__

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

enum strtoi_generic_typename {
        STRTOI_GENERIC_TYPENAME_OTHER = 0,
	/* signed integer types: */
        STRTOI_GENERIC_TYPENAME_SIGNED = 1,
        STRTOI_GENERIC_TYPENAME_SIGNED_CHAR,
        STRTOI_GENERIC_TYPENAME_SIGNED_SHORT,
        STRTOI_GENERIC_TYPENAME_SIGNED_INT,
        STRTOI_GENERIC_TYPENAME_SIGNED_LONG,
        STRTOI_GENERIC_TYPENAME_SIGNED_LONG_LONG,
	/* unsigned integer types: */
        STRTOI_GENERIC_TYPENAME_UNSIGNED = SCHAR_MAX,
        STRTOI_GENERIC_TYPENAME_UNSIGNED_CHAR,
        STRTOI_GENERIC_TYPENAME_UNSIGNED_SHORT,
        STRTOI_GENERIC_TYPENAME_UNSIGNED_INT,
        STRTOI_GENERIC_TYPENAME_UNSIGNED_LONG,
        STRTOI_GENERIC_TYPENAME_UNSIGNED_LONG_LONG,
};

#define STRTOI_GENERIC_TYPENAME(x) _Generic((x), \
	signed char:		STRTOI_GENERIC_TYPENAME_SIGNED_CHAR, \
	signed short:		STRTOI_GENERIC_TYPENAME_SIGNED_SHORT, \
	signed int:		STRTOI_GENERIC_TYPENAME_SIGNED_INT, \
	signed long:		STRTOI_GENERIC_TYPENAME_SIGNED_LONG, \
	signed long long:	STRTOI_GENERIC_TYPENAME_SIGNED_LONG_LONG, \
        unsigned char:		STRTOI_GENERIC_TYPENAME_UNSIGNED_CHAR, \
        unsigned short:		STRTOI_GENERIC_TYPENAME_UNSIGNED_SHORT, \
        unsigned int:		STRTOI_GENERIC_TYPENAME_UNSIGNED_INT, \
        unsigned long:		STRTOI_GENERIC_TYPENAME_UNSIGNED_LONG, \
        unsigned long long:	STRTOI_GENERIC_TYPENAME_UNSIGNED_LONG_LONG, \
        default:		STRTOI_GENERIC_TYPENAME_OTHER)

#define STRTOI_GENERIC_INTMIN(x) \
	((long long)__STRTOI_GENERIC_INTMIN(x))
#define __STRTOI_GENERIC_INTMIN(x) _Generic((x), \
	char:			CHAR_MIN, \
        signed char:		SCHAR_MIN, \
        signed short:		SHRT_MIN, \
        signed int:		INT_MIN, \
        signed long:		LONG_MIN, \
        signed long long:	LLONG_MIN, \
        unsigned char:		0, \
        unsigned short:		0, \
        unsigned int:		0, \
        unsigned long:		0, \
        unsigned long long:	0, \
        default:		0)

#define STRTOI_GENERIC_INTMAX(x) \
	((unsigned long long)__STRTOI_GENERIC_INTMAX(x))
#define __STRTOI_GENERIC_INTMAX(x) _Generic((x), \
	char:			CHAR_MAX, \
        signed char:		SCHAR_MAX, \
        signed short:		SHRT_MAX, \
        signed int:		INT_MAX, \
        signed long:		LONG_MAX, \
        signed long long:	LLONG_MAX, \
        unsigned char:		UCHAR_MAX, \
        unsigned short:		USHRT_MAX, \
        unsigned int:		UINT_MAX, \
        unsigned long:		ULONG_MAX, \
        unsigned long long:	ULLONG_MAX, \
        default: 0)

static inline int
strtoi_generic_func(const char *str,
		    long long min,
		    unsigned long long max,
		    enum strtoi_generic_typename type,
		    int base,
		    long long *num)
{
        long long ret;
        char *endptr;

	if (!type)
		return -ENOTSUP;

        errno = 0;
	if (type > STRTOI_GENERIC_TYPENAME_UNSIGNED)
	        ret = (long long)strtoull(str, &endptr, base);
	else
	        ret = strtoll(str, &endptr, base);

        if (str == endptr || *endptr != '\0' ||
            (errno && errno != ERANGE))
                return -EINVAL;
	if (errno == ERANGE)
		return -ERANGE;
	if (type > STRTOI_GENERIC_TYPENAME_UNSIGNED) {
		/* treat negative numbers for an unsigned type as -ERANGE,
		 * don't let strtoull() get away with its automatic
		 * conversion/negation
		 */
		if (strchr(str, '-') || (unsigned long long)ret > max)
			return -ERANGE;
	/* signed integer, from strtoll(): */
	} else if (ret < min || (ret > 0 && (unsigned long long)ret > max)) {
		return -ERANGE;
	}

	*num = ret;
        return 0;
}

/**
 * strtoi_base_generic() - convert a string to a generic integer (with base)
 * @str: a string to convert to an integer
 * @base: a base between 2 and 36, or the special value 0 (see strtoul())
 * @res: a pointer to an integer variable to store the result in
 *
 * Similar to strtoul() but the return value is only used for
 * error checking and a pointer for storing the result.
 *
 * Also checks that the result would fit into the range of the
 * provided integer type.
 *
 * Signature is like:
 *
 *   (static inline)
 *	int strtoi_base_generic(const char *str,
 *				<integer-type> *res,
 *				int base)
 *
 * * Return:
 * * %0		- On success
 * * %-ENOTSUP	- If the type of @res is not supported
 * * %-ERANGE	- If the value is out-of-range for the type of @res
 * * %-EINVAL	- For any other parsing error
 */
#define strtoi_base_generic(str, base, res) \
	({ \
		const char *_str = str; \
		int _base = base; \
		typeof(res) _res = res; \
		\
		long long num; \
		int ret; \
		\
		ret = strtoi_generic_func(_str, \
					  STRTOI_GENERIC_INTMIN(*_res), \
					  STRTOI_GENERIC_INTMAX(*_res), \
					  STRTOI_GENERIC_TYPENAME(*_res), \
					  _base, \
					  &num); \
		if (ret >= 0) \
			*_res = (typeof(*_res))num; \
		\
		ret; \
	})

/**
 * strtoi_generic() - convert a string to a generic integer
 * @str: a string to convert to an integer
 * @res: a pointer to an integer variable to store the result in
 *
 * Similar to strtoul() but the return value is only used for
 * error checking and a pointer is used for storing the result.
 * Uses a base 0 internally, like in strto*() functions.
 *
 * Also checks that the result would fit into the range of the
 * provided integer type.
 *
 * Signature is like:
 *
 *   (static inline)
 *	int strtoi_generic(const char *str,
 *			   <integer-type> *res)
 *
 * Return:
 * * %0		- On success
 * * %-ENOTSUP	- If the type of @res is not supported
 * * %-ERANGE	- If the value is out-of-range for the type of @res
 * * %-EINVAL	- For any other parsing error
 */
#define strtoi_generic(str, res) \
	strtoi_base_generic(str, 0, res)

#endif /* __STRTOI_GENERIC_H__ */
