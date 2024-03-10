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

		char *mem = malloc(mem_size);
		if (mem == NULL) {
			goto err;
		}

		struct sfdo_string *dirs = calloc(n_dirs, sizeof(*dirs));
		if (dirs == NULL) {
			free(mem);
			goto err;
		}

		char *mem_iter = mem;
		struct sfdo_string *dir_iter = dirs;

		dir_iter->data = mem_iter;
		dir_iter->len = home_len + sizeof(ICONS_HOME_DIR) - 1;
		memcpy(mem_iter, home, home_len);
		mem_iter += home_len;
		memcpy(mem_iter, ICONS_HOME_DIR, sizeof(ICONS_HOME_DIR));
		mem_iter += sizeof(ICONS_HOME_DIR);
		++dir_iter;

		for (size_t i = 0; i < n_data_dirs; i++) {
			const struct sfdo_string *dir = &data_dirs[i];
			dir_iter->data = mem_iter;
			dir_iter->len = dir->len + sizeof(ICONS_SUFFIX) - 1;
			memcpy(mem_iter, dir->data, dir->len);
			mem_iter += dir->len;
			memcpy(mem_iter, ICONS_SUFFIX, sizeof(ICONS_SUFFIX));
			mem_iter += sizeof(ICONS_SUFFIX);
			++dir_iter;
		}

		dir_iter->data = PIXMAPS_BASE_DIR;
		dir_iter->len = sizeof(PIXMAPS_BASE_DIR) - 1;

		ctx->default_basedirs = dirs;
		ctx->default_basedirs_mem = mem;
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
