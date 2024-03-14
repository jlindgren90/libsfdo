#ifndef SFDO_ICON_H
#define SFDO_ICON_H

#include <sfdo-common.h>
#include <stdbool.h>

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
	SFDO_ICON_THEME_LOAD_OPTIONS_DEFAULT = 0,

	SFDO_ICON_THEME_LOAD_OPTION_RELAXED = 1 << 0,
};

enum sfdo_icon_theme_lookup_options {
	SFDO_ICON_THEME_LOOKUP_OPTIONS_DEFAULT = 0,

	SFDO_ICON_THEME_LOOKUP_OPTION_NO_SVG = (1 << 0),
};

extern const struct sfdo_icon_file *const sfdo_icon_file_none;

struct sfdo_icon_ctx *sfdo_icon_ctx_create(struct sfdo_basedir_ctx *basedir_ctx);

void sfdo_icon_ctx_destroy(struct sfdo_icon_ctx *ctx);

void sfdo_icon_ctx_set_log_handler(struct sfdo_icon_ctx *ctx, enum sfdo_log_level level,
		sfdo_log_handler_func_t func, void *data);

struct sfdo_icon_theme *sfdo_icon_theme_load(
		struct sfdo_icon_ctx *ctx, const char *name, int options);

struct sfdo_icon_theme *sfdo_icon_theme_load_from(struct sfdo_icon_ctx *ctx, const char *name,
		const struct sfdo_string *basedirs, size_t n_basedirs, int options);

void sfdo_icon_theme_destroy(struct sfdo_icon_theme *theme);

bool sfdo_icon_theme_rescan(struct sfdo_icon_theme *theme);

struct sfdo_icon_file *sfdo_icon_theme_lookup(struct sfdo_icon_theme *theme, const char *name,
		size_t name_len, int size, int scale, int options);

struct sfdo_icon_file *sfdo_icon_theme_lookup_best(struct sfdo_icon_theme *theme,
		const struct sfdo_string *names, size_t n_names, int size, int scale, int options);

void sfdo_icon_file_destroy(struct sfdo_icon_file *file);

const char *sfdo_icon_file_get_path(struct sfdo_icon_file *file, size_t *len);

enum sfdo_icon_file_format sfdo_icon_file_get_format(struct sfdo_icon_file *file);

#endif
