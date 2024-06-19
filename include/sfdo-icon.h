#ifndef SFDO_ICON_H
#define SFDO_ICON_H

#include <sfdo-common.h>
#include <stdbool.h>

// libsfdo-icon implements the icon theme specification:
//
//  https://specifications.freedesktop.org/icon-theme-spec/icon-theme-spec-latest.html
//
// Note that the icon lookup algorithm used by libsfdo-icon doesn't match the specification;
// instead, an algorithm similar to GTK's is used as it results in better matches.

// Indicates that looking up an icon has failed.
#define SFDO_ICON_FILE_INVALID ((struct sfdo_icon_file *)-1)

struct sfdo_basedir_ctx;

struct sfdo_icon_ctx;

struct sfdo_icon_theme;

enum sfdo_icon_file_format {
	SFDO_ICON_FILE_FORMAT_PNG,
	SFDO_ICON_FILE_FORMAT_SVG,
	SFDO_ICON_FILE_FORMAT_XPM,
};

struct sfdo_icon_file;

enum sfdo_icon_theme_load_options {
	// The default icon theme loading options.
	SFDO_ICON_THEME_LOAD_OPTIONS_DEFAULT = 0,

	// If this flag is set, the loader will impose less restrictions on the format of icon theme
	// files. This option only exists because there are too many non-conformant themes in the wild.
	// It is advised that you don't set this flag by default and instead offer a way for a user to
	// set it manually.
	SFDO_ICON_THEME_LOAD_OPTION_RELAXED = 1 << 0,

	// If this flag is set, the loader will continue loading even if it fails to find a theme or one
	// of its dependencies.
	SFDO_ICON_THEME_LOAD_OPTION_ALLOW_MISSING = 1 << 1,
};

enum sfdo_icon_theme_lookup_options {
	// The default icon theme lookup options.
	SFDO_ICON_THEME_LOOKUP_OPTIONS_DEFAULT = 0,

	// If this flag is set, SVG icons will be ignored.
	SFDO_ICON_THEME_LOOKUP_OPTION_NO_SVG = (1 << 0),

	// If this flag is set, no automatic rescan will be performed. By default, looking up an icon
	// will trigger a theme rescan, unless it has been already done less than 5 seconds ago.
	SFDO_ICON_THEME_LOOKUP_OPTION_NO_RESCAN = (1 << 1),
};

// Create a context.
//
// basedir_ctx is used to create the default list of paths which are scanned for icon themes.
// basedir_ctx may be NULL, in which case the default list is empty.
//
// Returns NULL on memory allocation error.
struct sfdo_icon_ctx *sfdo_icon_ctx_create(struct sfdo_basedir_ctx *basedir_ctx);

// Destroy a context.
//
// ctx may be NULL, in which case the function is no-op.
void sfdo_icon_ctx_destroy(struct sfdo_icon_ctx *ctx);

// Set the context log handler.
//
// func will be called for each message with a level lower than or equal to level. func may be NULL.
void sfdo_icon_ctx_set_log_handler(struct sfdo_icon_ctx *ctx, enum sfdo_log_level level,
		sfdo_log_handler_func_t func, void *data);

// Load an icon theme by a name from the default list of paths.
//
// name may be NULL, in which case the default icon theme will be loaded.
//
// options is a result of bitwise OR of zero or more enum sfdo_icon_theme_load_options values.
//
// Returns NULL on failure.
struct sfdo_icon_theme *sfdo_icon_theme_load(
		struct sfdo_icon_ctx *ctx, const char *name, int options);

// Load an icon theme by a name.
//
// name may be NULL, in which case the default icon theme will be loaded.
//
// options is a result of bitwise OR of zero or more enum sfdo_icon_theme_load_options values.
//
// Returns NULL on failure.
struct sfdo_icon_theme *sfdo_icon_theme_load_from(struct sfdo_icon_ctx *ctx, const char *name,
		const struct sfdo_string *basedirs, size_t n_basedirs, int options);

// Destroy an icon theme.
//
// theme may be NULL, in which case the function is no-op.
void sfdo_icon_theme_destroy(struct sfdo_icon_theme *theme);

// Forcefully rescan the icon theme directories.
//
// Returns true on success, false otherwise.
bool sfdo_icon_theme_rescan(struct sfdo_icon_theme *theme);

// Find the best matching icon file by name, size, and scale.
//
// options is a result of bitwise OR of zero or more enum sfdo_icon_theme_lookup_options values.
//
// If name_len is equal to SFDO_NT, name is assumed to be null-terminated.
//
// Returns NULL if no file has been found, or SFDO_ICON_FILE_INVALID on failure.
struct sfdo_icon_file *sfdo_icon_theme_lookup(struct sfdo_icon_theme *theme, const char *name,
		size_t name_len, int size, int scale, int options);

// Find the best matching icon file by names, size, and scale.
//
// options is a result of bitwise OR of zero or more enum sfdo_icon_theme_lookup_options values.
//
// If name_len is equal to SFDO_NT, name is assumed to be null-terminated.
//
// Returns NULL if no file has been found, or SFDO_ICON_FILE_INVALID on failure.
struct sfdo_icon_file *sfdo_icon_theme_lookup_best(struct sfdo_icon_theme *theme,
		const struct sfdo_string *names, size_t n_names, int size, int scale, int options);

// Destroy an icon file.
//
// file may be NULL or SFDO_ICON_FILE_INVALID, in which case the function is no-op.
void sfdo_icon_file_destroy(struct sfdo_icon_file *file);

// Get an icon file path.
//
// The length of the path is saved to len. len may be NULL.
const char *sfdo_icon_file_get_path(struct sfdo_icon_file *file, size_t *len);

// Get an icon file format.
enum sfdo_icon_file_format sfdo_icon_file_get_format(struct sfdo_icon_file *file);

#endif
