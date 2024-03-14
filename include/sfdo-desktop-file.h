#ifndef SFDO_DESKTOP_FILE_H
#define SFDO_DESKTOP_FILE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

enum sfdo_desktop_file_error_code {
	SFDO_DESKTOP_FILE_ERROR_NONE = 0,

	SFDO_DESKTOP_FILE_ERROR_IO,
	SFDO_DESKTOP_FILE_ERROR_NT,
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

struct sfdo_desktop_file_group;

struct sfdo_desktop_file_entry;

enum sfdo_desktop_file_load_options {
	SFDO_DESKTOP_FILE_LOAD_OPTIONS_DEFAULT = 0,

	SFDO_DESKTOP_FILE_LOAD_ALLOW_DUPLICATE_GROUPS = 1 << 0,
};

typedef bool (*sfdo_desktop_file_group_handler_t)(
		struct sfdo_desktop_file_group *group, void *data);

bool sfdo_desktop_file_load(FILE *fp, struct sfdo_desktop_file_error *error, const char *locale,
		sfdo_desktop_file_group_handler_t group_handler, void *data, int options);

const char *sfdo_desktop_file_error_code_get_description(enum sfdo_desktop_file_error_code code);

const char *sfdo_desktop_file_group_get_name(struct sfdo_desktop_file_group *group, size_t *len);

void sfdo_desktop_file_group_get_location(
		struct sfdo_desktop_file_group *group, int *line, int *column);

struct sfdo_desktop_file_entry *sfdo_desktop_file_group_get_entry(
		struct sfdo_desktop_file_group *group, const char *key, size_t key_len);

const char *sfdo_desktop_file_entry_get_key(struct sfdo_desktop_file_entry *entry, size_t *len);

const char *sfdo_desktop_file_entry_get_value(struct sfdo_desktop_file_entry *entry, size_t *len);

void sfdo_desktop_file_entry_get_location(
		struct sfdo_desktop_file_entry *entry, int *line, int *column);

#endif
