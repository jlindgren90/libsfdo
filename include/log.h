#ifndef LOG_H
#define LOG_H

#include <sfdo-common.h>

struct sfdo_logger {
	enum sfdo_log_level level;
	sfdo_log_handler_func_t func;
	void *data;
};

void logger_setup(struct sfdo_logger *logger);

void logger_configure(struct sfdo_logger *logger, enum sfdo_log_level level,
		sfdo_log_handler_func_t func, void *data);

#ifdef __GNUC__
#define SFDO_ATTRIBUTE_PRINTF(start, end) __attribute__((format(printf, start, end)))
#else
#define SFDO_ATTRIBUTE_PRINTF(start, end)
#endif

void logger_write(struct sfdo_logger *logger, enum sfdo_log_level level, const char *fmt, ...)
		SFDO_ATTRIBUTE_PRINTF(3, 4);

#undef SFDO_ATTRIBUTE_PRINTF

void logger_write_oom(struct sfdo_logger *logger);

#endif
