#include <assert.h>
#include <sfdo-basedir.h>
#include <sfdo-icon.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "icon.h"

// Note: at the moment of writing this, the icon theme specification
// (https://specifications.freedesktop.org/icon-theme-spec/icon-theme-spec-latest.html)
// has a number of problems, for example:
//
// - https://gitlab.freedesktop.org/xdg/default-icon-theme/-/issues/19
// - https://gitlab.freedesktop.org/xdg/default-icon-theme/-/issues/20
//
// As such, some parts of this code (marked with SPEC) don't conform to the specification.

#define ICONS_HOME_DIR "/.icons/"
#define ICONS_SUFFIX "icons/"
#define PIXMAPS_BASE_DIR "/usr/share/pixmaps/"

SFDO_API struct sfdo_icon_ctx *sfdo_icon_ctx_create(struct sfdo_basedir_ctx *basedir_ctx) {
	struct sfdo_icon_ctx *ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL) {
		return NULL;
	}

	logger_setup(&ctx->logger);

	if (basedir_ctx != NULL) {
		const char *home = getenv("HOME");
		if (home == NULL) {
			home = "";
		}
		size_t home_len = strlen(home);

		size_t n_data_dirs;
		const struct sfdo_string *data_dirs = sfdo_basedir_get_data_dirs(basedir_ctx, &n_data_dirs);
		size_t n_dirs = n_data_dirs + 2;

		size_t mem_size = home_len + sizeof(ICONS_HOME_DIR);
		for (size_t i = 0; i < n_data_dirs; i++) {
			mem_size += data_dirs[i].len + sizeof(ICONS_SUFFIX);
		}

		struct sfdo_string *dirs = calloc(n_dirs, sizeof(*dirs));
		if (dirs == NULL) {
			goto err;
		}

		struct sfdo_strbuild mem_buf;
		if (!sfdo_strbuild_setup_capped(&mem_buf, mem_size)) {
			free(dirs);
			goto err;
		}

		struct sfdo_string *dir_iter = dirs;

		dir_iter->data = mem_buf.data + mem_buf.len;
		// ICONS_HOME_DIR includes a null terminator
		sfdo_strbuild_add_raw(
				&mem_buf, home, home_len, ICONS_HOME_DIR, sizeof(ICONS_HOME_DIR), NULL);
		dir_iter->len = mem_buf.len - 1;
		++dir_iter;

		for (size_t i = 0; i < n_data_dirs; i++) {
			size_t prev_len = mem_buf.len;
			const struct sfdo_string *data_dir = &data_dirs[i];
			dir_iter->data = mem_buf.data + mem_buf.len;
			// ICONS_SUFFIX includes a null terminator
			sfdo_strbuild_add_raw(&mem_buf, data_dir->data, data_dir->len, ICONS_SUFFIX,
					sizeof(ICONS_SUFFIX), NULL);
			dir_iter->len = mem_buf.len - prev_len - 1;
			++dir_iter;
		}

		assert(mem_buf.len == mem_buf.cap);

		dir_iter->data = PIXMAPS_BASE_DIR;
		dir_iter->len = sizeof(PIXMAPS_BASE_DIR) - 1;

		ctx->default_basedirs = dirs;
		ctx->default_basedirs_mem = mem_buf.data;
		ctx->default_n_basedirs = n_dirs;
	}

	return ctx;

err:
	sfdo_icon_ctx_destroy(ctx);
	return NULL;
}

SFDO_API void sfdo_icon_ctx_destroy(struct sfdo_icon_ctx *ctx) {
	free(ctx->default_basedirs);
	free(ctx->default_basedirs_mem);
	free(ctx);
}

SFDO_API void sfdo_icon_ctx_set_log_handler(struct sfdo_icon_ctx *ctx, enum sfdo_log_level level,
		sfdo_log_handler_func_t func, void *data) {
	logger_configure(&ctx->logger, level, func, data);
}
