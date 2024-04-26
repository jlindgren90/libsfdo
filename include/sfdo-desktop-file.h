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
};

struct sfdo_desktop_file_error {
	enum sfdo_desktop_file_error_code code;
	int line, column;
};

struct sfdo_desktop_file_document;

struct sfdo_desktop_file_group;

struct sfdo_desktop_file_entry;

enum sfdo_desktop_file_load_options {
	// The default desktop entry file loading options.
	SFDO_DESKTOP_FILE_LOAD_OPTIONS_DEFAULT = 0,

	// If this flag is set, the loader will allow groups with the same names. It becomes the
	// responsibility of the caller to handle duplicate groups correctly.
	SFDO_DESKTOP_FILE_LOAD_ALLOW_DUPLICATE_GROUPS = 1 << 0,
};

// Load a document.
//
// locale is a string of form lang_COUNTRY.ENCODING@MODIFIER, where _COUNTRY, .ENCODING, and
// @MODIFIER may be omitted. It is used to select the best values for localized strings. May be
// NULL.
//
// options is a result of bitwise OR of zero or more enum sfdo_desktop_file_load_options values.
//
// On failure, the information about the error is saved to error. error may be NULL.
//
// Returns NULL on failure.
struct sfdo_desktop_file_document *sfdo_desktop_file_document_load(
		FILE *fp, const char *locale, int options, struct sfdo_desktop_file_error *error);

// Destroy a document.
//
// document may be NULL, in which case the function is no-op.
void sfdo_desktop_file_document_destroy(struct sfdo_desktop_file_document *document);

// Get the first group of the document.
//
// Returns NULL if the document has no groups.
struct sfdo_desktop_file_group *sfdo_desktop_file_document_get_groups(
		struct sfdo_desktop_file_document *document);

// Get the description of an error by its code.
const char *sfdo_desktop_file_error_code_get_description(enum sfdo_desktop_file_error_code code);

// Get the next group of the document.
//
// Returns NULL if there is no next group.
struct sfdo_desktop_file_group *sfdo_desktop_file_group_get_next(
		struct sfdo_desktop_file_group *group);

// Get the name of a group.
//
// The length of the name is saved to len. len may be NULL.
const char *sfdo_desktop_file_group_get_name(struct sfdo_desktop_file_group *group, size_t *len);

// Get the group location in the file.
//
// The location is saved to line and column. line and column may be NULL.
void sfdo_desktop_file_group_get_location(
		struct sfdo_desktop_file_group *group, int *line, int *column);

// Get an entry from a group by a key.
//
// If key_len is equal to SFDO_NT, key is assumed to be null-terminated.
//
// Returns NULL if there is no matching entry.
struct sfdo_desktop_file_entry *sfdo_desktop_file_group_get_entry(
		struct sfdo_desktop_file_group *group, const char *key, size_t key_len);

// Get the entry key.
//
// The length of the key is saved to len. len may be NULL.
const char *sfdo_desktop_file_entry_get_key(struct sfdo_desktop_file_entry *entry, size_t *len);

// Get the entry value.
//
// The length of the value is saved to len. len may be NULL.
const char *sfdo_desktop_file_entry_get_value(struct sfdo_desktop_file_entry *entry, size_t *len);

// Get the entry location in the file.
//
// The location is saved to line and column. line and column may be NULL.
void sfdo_desktop_file_entry_get_location(
		struct sfdo_desktop_file_entry *entry, int *line, int *column);

#endif
