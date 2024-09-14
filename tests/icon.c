#include <sfdo-icon.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

static void log_handler(enum sfdo_log_level level, const char *fmt, va_list args, void *data) {
	(void)level;
	(void)data;
	static const char *levels[] = {
		[SFDO_LOG_LEVEL_SILENT] = "",
		[SFDO_LOG_LEVEL_ERROR] = "error",
		[SFDO_LOG_LEVEL_INFO] = "info",
		[SFDO_LOG_LEVEL_DEBUG] = "debug",
	};
	fprintf(stdout, "[%s] ", levels[level]);
	vfprintf(stdout, fmt, args);
	fprintf(stdout, "\n");
}

static struct sfdo_icon_theme *load_theme(
		struct sfdo_icon_ctx *ctx, const char *name, int options) {
	static const struct sfdo_string basedirs[] = {
		{
			.data = "icon/basedir1",
			.len = 13,
		},
	};

	return sfdo_icon_theme_load_from(
			ctx, name, basedirs, sizeof(basedirs) / sizeof(*basedirs), options);
}

static struct sfdo_icon_theme *load_success(
		struct sfdo_icon_ctx *ctx, const char *name, int options) {
	struct sfdo_icon_theme *theme = load_theme(ctx, name, options);
	if (theme == NULL) {
		fprintf(stderr, "\"%s\" unexpected error\n", name);
		exit(1);
	}

	return theme;
}

static void load_error(struct sfdo_icon_ctx *ctx, const char *name, int options) {
	struct sfdo_icon_theme *theme = load_theme(ctx, name, options);
	if (theme != NULL) {
		fprintf(stderr, "\"%s\" unexpected error\n", name);
		exit(1);
	}
}

static struct sfdo_icon_file *lookup(const char *case_name, struct sfdo_icon_theme *theme,
		const char *name, int size, int scale, int options) {
	struct sfdo_icon_file *file =
			sfdo_icon_theme_lookup(theme, name, SFDO_NT, size, scale, options);
	if (file == SFDO_ICON_FILE_INVALID) {
		fprintf(stderr, "\"%s\" runtime icon lookup error\n", case_name);
		exit(1);
	}

	return file;
}

static void lookup_success(const char *case_name, struct sfdo_icon_theme *theme, const char *name,
		int size, int scale, int options, enum sfdo_icon_file_format exp_format,
		const char *exp_path) {
	struct sfdo_icon_file *file = lookup(case_name, theme, name, size, scale, options);
	if (file == NULL) {
		fprintf(stderr, "\"%s\" unexpected icon lookup error\n", case_name);
		exit(1);
	}

	const char *got_path = sfdo_icon_file_get_path(file, NULL);
	if (strcmp(exp_path, got_path) != 0) {
		fprintf(stderr, "\"%s\" path mismatch: expected %s, got %s\n", case_name, exp_path,
				got_path);
		exit(1);
	}

	enum sfdo_icon_file_format got_format = sfdo_icon_file_get_format(file);
	if (exp_format != got_format) {
		static const char *format_names[] = {
			[SFDO_ICON_FILE_FORMAT_PNG] = "png",
			[SFDO_ICON_FILE_FORMAT_SVG] = "svg",
			[SFDO_ICON_FILE_FORMAT_XPM] = "xpm",
		};
		fprintf(stderr, "\"%s\" format mismatch: expected %s, got %s\n", case_name,
				format_names[exp_format], format_names[got_format]);
		exit(1);
	}

	sfdo_icon_file_destroy(file);
}

static void lookup_error(const char *case_name, struct sfdo_icon_theme *theme, const char *name,
		int size, int scale, int options) {
	struct sfdo_icon_file *file = lookup(case_name, theme, name, size, scale, options);
	if (file != NULL) {
		fprintf(stderr, "\"%s\" unexpected icon lookup success\n", case_name);
		exit(1);
	}
}

int main(void) {
	// Update cache mtime to ensure it's not stale
	utimes("icon/basedir1/cached/icon-theme.cache", NULL);

	struct sfdo_icon_ctx *ctx = sfdo_icon_ctx_create(NULL);
	sfdo_icon_ctx_set_log_handler(ctx, SFDO_LOG_LEVEL_DEBUG, log_handler, NULL);

	struct sfdo_icon_theme *theme;

	theme = load_success(ctx, "hicolor", SFDO_ICON_THEME_LOAD_OPTIONS_DEFAULT);
	lookup_success("fixed", theme, "fixed", 16, 1, SFDO_ICON_THEME_LOOKUP_OPTIONS_DEFAULT,
			SFDO_ICON_FILE_FORMAT_PNG, "icon/basedir1/hicolor/fixed/fixed.png");
	lookup_success("scalable", theme, "scalable", 32, 1, SFDO_ICON_THEME_LOOKUP_OPTIONS_DEFAULT,
			SFDO_ICON_FILE_FORMAT_SVG, "icon/basedir1/hicolor/scalable/nested/scalable.svg");
	lookup_success("fallback", theme, "fallback", 24, 1, SFDO_ICON_THEME_LOOKUP_OPTIONS_DEFAULT,
			SFDO_ICON_FILE_FORMAT_PNG, "icon/basedir1/fallback.png");
	lookup_error(
			"nonexistent", theme, "nonexistent", 24, 1, SFDO_ICON_THEME_LOOKUP_OPTIONS_DEFAULT);
	sfdo_icon_theme_destroy(theme);

	load_error(ctx, "nonexistent", SFDO_ICON_THEME_LOAD_OPTIONS_DEFAULT);
	sfdo_icon_theme_destroy(
			load_success(ctx, "nonexistent", SFDO_ICON_THEME_LOAD_OPTION_ALLOW_MISSING));

	theme = load_success(ctx, "loop-first", SFDO_ICON_THEME_LOAD_OPTIONS_DEFAULT);
	lookup_success("loop-first", theme, "loop", 16, 1, SFDO_ICON_THEME_LOOKUP_OPTIONS_DEFAULT,
			SFDO_ICON_FILE_FORMAT_PNG, "icon/basedir1/loop-first/dir/loop.png");
	sfdo_icon_theme_destroy(theme);

	theme = load_success(ctx, "loop-second", SFDO_ICON_THEME_LOAD_OPTIONS_DEFAULT);
	lookup_success("loop-second", theme, "loop", 16, 1, SFDO_ICON_THEME_LOOKUP_OPTIONS_DEFAULT,
			SFDO_ICON_FILE_FORMAT_PNG, "icon/basedir1/loop-second/dir/loop.png");
	sfdo_icon_theme_destroy(theme);

	theme = load_success(ctx, "cached", SFDO_ICON_THEME_LOAD_OPTIONS_DEFAULT);
	lookup_error("cached", theme, "placeholder", 24, 1, SFDO_ICON_THEME_LOOKUP_OPTION_NO_RESCAN);

	lookup_success("cached foo", theme, "foo", 24, 1, SFDO_ICON_THEME_LOOKUP_OPTION_NO_RESCAN,
			SFDO_ICON_FILE_FORMAT_PNG, "icon/basedir1/cached/24x24/foo.png");
	lookup_success("cached something", theme, "something", 24, 1,
			SFDO_ICON_THEME_LOOKUP_OPTION_NO_RESCAN, SFDO_ICON_FILE_FORMAT_SVG,
			"icon/basedir1/cached/24x24/something.svg");

	lookup_success("cached multi 24", theme, "multi", 24, 1,
			SFDO_ICON_THEME_LOOKUP_OPTION_NO_RESCAN, SFDO_ICON_FILE_FORMAT_PNG,
			"icon/basedir1/cached/24x24/multi.png");

	lookup_success("cached multi 22", theme, "multi", 22, 1,
			SFDO_ICON_THEME_LOOKUP_OPTION_NO_RESCAN, SFDO_ICON_FILE_FORMAT_SVG,
			"icon/basedir1/cached/22x22/multi.svg");
	lookup_success("cached multi 22 no_svg", theme, "multi", 22, 1,
			SFDO_ICON_THEME_LOOKUP_OPTION_NO_RESCAN | SFDO_ICON_THEME_LOOKUP_OPTION_NO_SVG,
			SFDO_ICON_FILE_FORMAT_XPM, "icon/basedir1/cached/22x22/multi.xpm");

	sfdo_icon_theme_destroy(theme);

	sfdo_icon_ctx_destroy(ctx);

	return 0;
}
