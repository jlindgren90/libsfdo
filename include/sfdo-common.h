#ifndef SFDO_COMMON_H
#define SFDO_COMMON_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdarg.h>
#include <stddef.h>

// Used to specify that a sequence of characters is null-terminated.
#define SFDO_NT ((size_t)(-1))

struct sfdo_string {
	const char *data; // UTF-8, null-terminated
	size_t len; // In octets, excluding the null terminator
};

enum sfdo_log_level {
	SFDO_LOG_LEVEL_SILENT,
	SFDO_LOG_LEVEL_ERROR,
	SFDO_LOG_LEVEL_INFO,
	SFDO_LOG_LEVEL_DEBUG,
};

typedef void (*sfdo_log_handler_func_t)(
		enum sfdo_log_level level, const char *fmt, va_list args, void *data);

#ifdef __cplusplus
}
#endif

#endif
