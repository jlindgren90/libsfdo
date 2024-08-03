#include <assert.h>
#include <sfdo-basedir.h>
#include <stdlib.h>
#include <string.h>

#include "common/api.h"
#include "common/membuild.h"
#include "common/path.h"
#include "common/striter.h"

#define DATA_HOME_FALLBACK "/.local/share/"
#define CONFIG_HOME_FALLBACK "/.config/"
#define STATE_HOME_FALLBACK "/.local/state/"
#define CACHE_HOME_FALLBACK "/.cache/"

#define DATA_DIRS_FALLBACK "/usr/local/share/:/usr/share/"
#define CONFIG_DIRS_FALLBACK "/etc/xdg/"

// Lists in ctx include home directories

struct sfdo_basedir_ctx {
	char *data_dirs_mem;
	struct sfdo_string *data_dirs;
	size_t n_data_dirs;

	char *config_dirs_mem;
	struct sfdo_string *config_dirs;
	size_t n_config_dirs;

	char *state_home_mem;
	struct sfdo_string state_home;

	char *cache_home_mem;
	struct sfdo_string cache_home;

	char *runtime_dir_mem;
	struct sfdo_string runtime_dir;
};

static inline bool is_unset_or_empty(const char *var) {
	return var == NULL || var[0] == '\0';
}

static inline bool is_absolute(const char *path) {
	return path[0] == '/';
}

static bool init_dir_list(struct sfdo_string **ptr, char **mem_ptr, size_t *n_dirs_ptr,
		const char *home, size_t home_len, const char *home_var_name, const char *home_fallback,
		size_t home_fallback_len, const char *list_var_name, const char *list_fallback) {
	const char *list = getenv(list_var_name);
	if (is_unset_or_empty(list)) {
		list = list_fallback;
	}

	const char *home_var_path = getenv(home_var_name);
	bool home_var_path_valid = !is_unset_or_empty(home_var_path) && is_absolute(home_var_path);

	size_t home_path_len;
	size_t mem_size;
	if (home_var_path_valid) {
		home_path_len = strlen(home_var_path);
		mem_size = home_path_len + 1;
		if (sfdo_path_needs_extra_slash(home_var_path, home_path_len)) {
			++mem_size;
		}
	} else {
		home_path_len = home_len + home_fallback_len;
		mem_size = home_path_len + 1;
	}

	size_t n_dirs = 1;

	size_t path_start, path_len;
	size_t iter = 0;

	while (sfdo_striter(list, ':', &iter, &path_start, &path_len)) {
		const char *path = list + path_start;
		if (path_len > 0 && is_absolute(path)) {
			++n_dirs;
			mem_size += path_len + 1;
			if (sfdo_path_needs_extra_slash(path, path_len)) {
				++mem_size;
			}
		}
	}

	struct sfdo_string *dirs = calloc(n_dirs, sizeof(*dirs));
	if (dirs == NULL) {
		return false;
	}

	struct sfdo_membuild mem_buf;
	if (!sfdo_membuild_setup(&mem_buf, mem_size)) {
		free(dirs);
		return false;
	}

	// Home directory
	size_t dir_i = 0;
	struct sfdo_string *dir = &dirs[dir_i++];
	dir->data = mem_buf.data + mem_buf.len;
	dir->len = home_path_len;

	if (home_var_path_valid) {
		sfdo_membuild_add(&mem_buf, home_var_path, home_path_len, NULL);
		if (sfdo_path_needs_extra_slash(home_var_path, home_path_len)) {
			sfdo_membuild_add(&mem_buf, "/", 1, NULL);
			++dir->len;
		}
	} else {
		sfdo_membuild_add(&mem_buf, home, home_len, home_fallback, home_fallback_len, NULL);
	}
	sfdo_membuild_add(&mem_buf, "", 1, NULL);

	iter = 0;
	while (sfdo_striter(list, ':', &iter, &path_start, &path_len)) {
		const char *path = list + path_start;
		if (path_len > 0 && is_absolute(path)) {
			dir = &dirs[dir_i++];
			dir->data = mem_buf.data + mem_buf.len;
			dir->len = path_len;
			sfdo_membuild_add(&mem_buf, path, path_len, NULL);
			if (sfdo_path_needs_extra_slash(path, path_len)) {
				sfdo_membuild_add(&mem_buf, "/", 1, NULL);
				++dir->len;
			}
			sfdo_membuild_add(&mem_buf, "", 1, NULL);
		}
	}

	assert(dir_i == n_dirs);
	assert(mem_buf.len == mem_size);

	*ptr = dirs;
	*mem_ptr = mem_buf.data;
	*n_dirs_ptr = n_dirs;
	return true;
}

static bool init_dir(struct sfdo_string *ptr, char **mem_ptr, const char *home, size_t home_len,
		const char *var_name, const char *home_fallback, size_t home_fallback_len) {
	const char *var_path = getenv(var_name);
	bool var_path_valid = !is_unset_or_empty(var_path) && is_absolute(var_path);

	size_t path_len;
	size_t mem_size;
	if (var_path_valid) {
		path_len = strlen(var_path);
		mem_size = path_len + 1;
		if (sfdo_path_needs_extra_slash(var_path, path_len)) {
			++mem_size;
		}
	} else {
		if (home_fallback == NULL) {
			return true;
		}
		path_len = home_len + home_fallback_len;
		mem_size = path_len + 1;
	}

	struct sfdo_membuild mem_buf;
	if (!sfdo_membuild_setup(&mem_buf, mem_size)) {
		return false;
	}

	ptr->data = mem_buf.data;
	ptr->len = path_len;

	if (var_path_valid) {
		sfdo_membuild_add(&mem_buf, var_path, path_len, NULL);
		if (sfdo_path_needs_extra_slash(var_path, path_len)) {
			sfdo_membuild_add(&mem_buf, "/", 1, NULL);
			++ptr->len;
		}
	} else {
		sfdo_membuild_add(&mem_buf, home, home_len, home_fallback, home_fallback_len, NULL);
	}
	sfdo_membuild_add(&mem_buf, "", 1, NULL);

	assert(mem_buf.len == mem_size);

	*mem_ptr = mem_buf.data;
	return true;
}

struct sfdo_basedir_ctx;

SFDO_API struct sfdo_basedir_ctx *sfdo_basedir_ctx_create(void) {
	struct sfdo_basedir_ctx *ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL) {
		return NULL;
	}

	const char *home = getenv("HOME");
	if (home == NULL) {
		// All home fallbacks start with "/" so results will be absolute paths
		home = "";
	}
	size_t home_len = strlen(home);

	if (!init_dir_list(&ctx->data_dirs, &ctx->data_dirs_mem, &ctx->n_data_dirs, home, home_len,
				"XDG_DATA_HOME", DATA_HOME_FALLBACK, sizeof(DATA_HOME_FALLBACK) - 1,
				"XDG_DATA_DIRS", DATA_DIRS_FALLBACK)) {
		goto err;
	}
	if (!init_dir_list(&ctx->config_dirs, &ctx->config_dirs_mem, &ctx->n_config_dirs, home,
				home_len, "XDG_CONFIG_HOME", CONFIG_HOME_FALLBACK, sizeof(CONFIG_HOME_FALLBACK) - 1,
				"XDG_CONFIG_DIRS", CONFIG_DIRS_FALLBACK)) {
		goto err;
	}

	if (!init_dir(&ctx->state_home, &ctx->state_home_mem, home, home_len, "XDG_STATE_HOME",
				STATE_HOME_FALLBACK, sizeof(STATE_HOME_FALLBACK) - 1)) {
		goto err;
	}
	if (!init_dir(&ctx->cache_home, &ctx->cache_home_mem, home, home_len, "XDG_CACHE_HOME",
				CACHE_HOME_FALLBACK, sizeof(CACHE_HOME_FALLBACK) - 1)) {
		goto err;
	}

	if (!init_dir(&ctx->runtime_dir, &ctx->runtime_dir_mem, home, home_len, "XDG_RUNTIME_DIR", NULL,
				0)) {
		goto err;
	}

	return ctx;

err:
	sfdo_basedir_ctx_destroy(ctx);
	return NULL;
}

SFDO_API void sfdo_basedir_ctx_destroy(struct sfdo_basedir_ctx *ctx) {
	if (ctx == NULL) {
		return;
	}

	free(ctx->data_dirs);
	free(ctx->config_dirs);

	free(ctx->data_dirs_mem);
	free(ctx->config_dirs_mem);
	free(ctx->state_home_mem);
	free(ctx->cache_home_mem);
	free(ctx->runtime_dir_mem);

	free(ctx);
}

SFDO_API const struct sfdo_string *sfdo_basedir_get_data_dirs(
		struct sfdo_basedir_ctx *ctx, size_t *n_directories) {
	*n_directories = ctx->n_data_dirs;
	return ctx->data_dirs;
}

SFDO_API const char *sfdo_basedir_get_data_home(struct sfdo_basedir_ctx *ctx, size_t *len) {
	struct sfdo_string *data_home = ctx->data_dirs;
	if (len != NULL) {
		*len = data_home->len;
	}
	return data_home->data;
}

SFDO_API const struct sfdo_string *sfdo_basedir_get_data_system_dirs(
		struct sfdo_basedir_ctx *ctx, size_t *n_directories) {
	*n_directories = ctx->n_data_dirs - 1;
	return ctx->data_dirs + 1;
}

SFDO_API const struct sfdo_string *sfdo_basedir_get_config_dirs(
		struct sfdo_basedir_ctx *ctx, size_t *n_directories) {
	*n_directories = ctx->n_config_dirs;
	return ctx->config_dirs;
}

SFDO_API const char *sfdo_basedir_get_config_home(struct sfdo_basedir_ctx *ctx, size_t *len) {
	struct sfdo_string *config_home = ctx->config_dirs;
	if (len != NULL) {
		*len = config_home->len;
	}
	return config_home->data;
}

SFDO_API const struct sfdo_string *sfdo_basedir_get_config_system_dirs(
		struct sfdo_basedir_ctx *ctx, size_t *n_directories) {
	*n_directories = ctx->n_config_dirs - 1;
	return ctx->config_dirs + 1;
}

SFDO_API const char *sfdo_basedir_get_state_home(struct sfdo_basedir_ctx *ctx, size_t *len) {
	if (len != NULL) {
		*len = ctx->state_home.len;
	}
	return ctx->state_home.data;
}

SFDO_API const char *sfdo_basedir_get_cache_home(struct sfdo_basedir_ctx *ctx, size_t *len) {
	if (len != NULL) {
		*len = ctx->cache_home.len;
	}
	return ctx->cache_home.data;
}

SFDO_API const char *sfdo_basedir_get_runtime_dir(struct sfdo_basedir_ctx *ctx, size_t *len) {
	if (len != NULL) {
		*len = ctx->runtime_dir.len;
	}
	return ctx->runtime_dir.data;
}
