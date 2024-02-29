#ifndef SFDO_BASEDIR_H
#define SFDO_BASEDIR_H

#include <sfdo-common.h>
#include <stdbool.h>

struct sfdo_basedir_ctx;

struct sfdo_basedir_ctx *sfdo_basedir_ctx_create(void);

void sfdo_basedir_ctx_destroy(struct sfdo_basedir_ctx *ctx);

const struct sfdo_string *sfdo_basedir_get_data_dirs(
		struct sfdo_basedir_ctx *ctx, size_t *n_directories);

const struct sfdo_string *sfdo_basedir_get_data_home(struct sfdo_basedir_ctx *ctx);

const struct sfdo_string *sfdo_basedir_get_data_system_dirs(
		struct sfdo_basedir_ctx *ctx, size_t *n_directories);

const struct sfdo_string *sfdo_basedir_get_config_dirs(
		struct sfdo_basedir_ctx *ctx, size_t *n_directories);

const struct sfdo_string *sfdo_basedir_get_config_home(struct sfdo_basedir_ctx *ctx);

const struct sfdo_string *sfdo_basedir_get_config_system_dirs(
		struct sfdo_basedir_ctx *ctx, size_t *n_directories);

const struct sfdo_string *sfdo_basedir_get_state_home(struct sfdo_basedir_ctx *ctx);

const struct sfdo_string *sfdo_basedir_get_cache_home(struct sfdo_basedir_ctx *ctx);

const struct sfdo_string *sfdo_basedir_get_runtime_dir(struct sfdo_basedir_ctx *ctx);

#endif
