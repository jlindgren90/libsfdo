#include <sfdo-basedir.h>
#include <sfdo-desktop.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "desktop.h"
#include "membuild.h"

#define APPLICATIONS_SUFFIX "applications/"

SFDO_API struct sfdo_desktop_ctx *sfdo_desktop_ctx_create(struct sfdo_basedir_ctx *basedir_ctx) {
	struct sfdo_desktop_ctx *ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL) {
		return NULL;
	}

	if (basedir_ctx != NULL) {
		size_t n_dirs;
		const struct sfdo_string *data_dirs = sfdo_basedir_get_data_dirs(basedir_ctx, &n_dirs);

		size_t mem_size = 0;
		for (size_t i = 0; i < n_dirs; i++) {
			mem_size += data_dirs[i].len + sizeof(APPLICATIONS_SUFFIX);
		}

		struct sfdo_string *dirs = calloc(n_dirs, sizeof(*dirs));
		if (dirs == NULL) {
			goto err;
		}

		struct sfdo_membuild mem_buf;
		if (!sfdo_membuild_setup(&mem_buf, mem_size)) {
			free(dirs);
			goto err;
		}

		for (size_t i = 0; i < n_dirs; i++) {
			const struct sfdo_string *data_dir = &data_dirs[i];
			dirs[i].data = mem_buf.data + mem_buf.len;
			// APPLICATIONS_SUFFIX includes a null terminator
			sfdo_membuild_add(&mem_buf, data_dir->data, data_dir->len, APPLICATIONS_SUFFIX,
					sizeof(APPLICATIONS_SUFFIX), NULL);
			dirs[i].len = data_dir->len + sizeof(APPLICATIONS_SUFFIX) - 1;
		}

		ctx->default_basedirs = dirs;
		ctx->default_basedirs_mem = mem_buf.data;
		ctx->default_n_basedirs = n_dirs;
	}

	return ctx;

err:
	sfdo_desktop_ctx_destroy(ctx);
	return NULL;
}

SFDO_API void sfdo_desktop_ctx_destroy(struct sfdo_desktop_ctx *ctx) {
	if (ctx == NULL) {
		return;
	}

	free(ctx->default_basedirs);
	free(ctx->default_basedirs_mem);
	free(ctx);
}

SFDO_API void sfdo_desktop_ctx_set_log_handler(struct sfdo_desktop_ctx *ctx,
		enum sfdo_log_level level, sfdo_log_handler_func_t func, void *data) {
	logger_configure(&ctx->logger, level, func, data);
}
