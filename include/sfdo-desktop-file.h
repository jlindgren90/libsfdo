#ifndef SFDO_DESKTOP_FILE_H
#define SFDO_DESKTOP_FILE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

enum sfdo_desktop_file_error_code {
	SFDO_DESKTOP_FILE_ERROR_NONE = 0,

	SFDO_DESKTOP_FILE_ERROR_IO,
	SFDO_DESKTOP_FILE_ERROR_UTF8,
	SFDO_DESKTOP_FILE_ERROR_OOM,
	SFDO_DESKTOP_FILE_ERROR_SYNTAX,
	SFDO_DESKTOP_FILE_ERROR_DUPLICATE_GROUP,
	SFDO_DESKTOP_FILE_ERROR_DUPLICATE_KEY,
	SFDO_DESKTOP_FILE_ERROR_NO_DEFAULT_VALUE,
	SFDO_DESKTOP_FILE_ERROR_USER,
};

struct sfdo_desktop_file_error {
	enum sfdo_desktop_file_error_code code;
	int line, column;
};

struct sfdo_desktop_file_group {
	const char *name;
	size_t name_len;
	int line, column;
};

struct sfdo_desktop_file_group_entry {
	const char *key;
	size_t key_len;
	const char *value;
	size_t value_len;
	int line, column;
};

typedef bool (*sfdo_desktop_file_group_entry_handler_t)(
		const struct sfdo_desktop_file_group_entry *entry, void *data);

typedef bool (*sfdo_desktop_file_group_end_handler_t)(
		const struct sfdo_desktop_file_group *group, void *data);

typedef bool (*sfdo_desktop_file_group_start_handler_t)(const struct sfdo_desktop_file_group *group,
		void *data, sfdo_desktop_file_group_entry_handler_t *out_entry_handler,
		sfdo_desktop_file_group_end_handler_t *out_end_handler);

bool sfdo_desktop_file_load(FILE *fp, struct sfdo_desktop_file_error *error, const char *locale,
		sfdo_desktop_file_group_start_handler_t group_start_handler, void *data);

const char *sfdo_desktop_file_error_code_get_description(enum sfdo_desktop_file_error_code code);

#endif
