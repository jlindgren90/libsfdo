#include <sfdo-basedir.h>
#include <stdio.h>
#include <stdlib.h>

static void print_dir(const char *name, const char *dir, size_t dir_len) {
	printf("%s: ", name);
	if (dir != NULL) {
		printf("%s (%zu bytes)\n", dir, dir_len);
	} else {
		printf("<unset, empty, or invalid>\n");
	}
}

static void print_dir_list(const char *name, const struct sfdo_string *dirs, size_t n_dirs) {
	printf("%s: %zu dirs\n", name, n_dirs);
	for (size_t i = 0; i < n_dirs; i++) {
		printf(" %zu: %s (%zu bytes)\n", i, dirs[i].data, dirs[i].len);
	}
}

int main(void) {
	struct sfdo_basedir_ctx *ctx = sfdo_basedir_ctx_create();
	if (ctx == NULL) {
		fprintf(stderr, "sfdo_basedir_ctx_create() failed\n");
		exit(1);
	}

	const char *dir;
	size_t dir_len;

	const struct sfdo_string *dirs;
	size_t n_dirs;

	dir = sfdo_basedir_get_data_home(ctx, &dir_len);
	print_dir("XDG_DATA_HOME", dir, dir_len);
	dirs = sfdo_basedir_get_data_system_dirs(ctx, &n_dirs);
	print_dir_list("XDG_DATA_DIRS", dirs, n_dirs);

	dir = sfdo_basedir_get_config_home(ctx, &dir_len);
	print_dir("XDG_CONFIG_HOME", dir, dir_len);
	dirs = sfdo_basedir_get_config_system_dirs(ctx, &n_dirs);
	print_dir_list("XDG_CONFIG_DIRS", dirs, n_dirs);

	dir = sfdo_basedir_get_state_home(ctx, &dir_len);
	print_dir("XDG_STATE_HOME", dir, dir_len);
	dir = sfdo_basedir_get_cache_home(ctx, &dir_len);
	print_dir("XDG_CACHE_HOME", dir, dir_len);

	dir = sfdo_basedir_get_runtime_dir(ctx, &dir_len);
	print_dir("XDG_RUNTIME_DIR", dir, dir_len);

	sfdo_basedir_ctx_destroy(ctx);
	return 0;
}
