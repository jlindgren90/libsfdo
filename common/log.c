#include "common/log.h"

static void noop_handler(enum sfdo_log_level level, const char *fmt, va_list args, void *data) {
	(void)level;
	(void)fmt;
	(void)args;
	(void)data;
}

void logger_setup(struct sfdo_logger *logger) {
	logger->level = SFDO_LOG_LEVEL_SILENT;
	logger->func = noop_handler;
	logger->data = NULL;
}

void logger_configure(struct sfdo_logger *logger, enum sfdo_log_level level,
		sfdo_log_handler_func_t func, void *data) {
	if (func == NULL) {
		func = noop_handler;
	}

	logger->level = level;
	logger->func = func;
	logger->data = data;
}

void logger_write(struct sfdo_logger *logger, enum sfdo_log_level level, const char *fmt, ...) {
	if (level > logger->level) {
		return;
	}
	va_list args;
	va_start(args, fmt);
	logger->func(level, fmt, args, logger->data);
	va_end(args);
}

void logger_write_oom(struct sfdo_logger *logger) {
	logger_write(logger, SFDO_LOG_LEVEL_ERROR, "Memory allocation failed");
}
