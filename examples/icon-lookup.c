#include <getopt.h>
#include <sfdo-basedir.h>
#include <sfdo-icon.h>
#include <stdio.h>
#include <stdlib.h>

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

static void die_usage(const char *prog) {
	printf("Usage: %s [-DS] <theme> <size> <scale> <names...>\n", prog);
	exit(1);
}

int main(int argc, char **argv) {
	int options = SFDO_ICON_THEME_LOOKUP_OPTIONS_DEFAULT;
	bool debug = false;

	char *prog = argv[0];
	int opt;
	while ((opt = getopt(argc, argv, "DS")) != -1) {
		switch (opt) {
		case 'S':
			options |= SFDO_ICON_THEME_LOOKUP_OPTION_NO_SVG;
			break;
		case 'D':
			debug = true;
			break;
		default:
			die_usage(prog);
		}
	}
	argv += optind;
	argc -= optind;

	if (argc < 4) {
		die_usage(prog);
	}

	const char *theme_name = argv[0];
	int size = atoi(argv[1]);
	int scale = atoi(argv[2]);

	argv += 3;
	argc -= 3;

	const char **names = (const char **)argv;
	size_t n_names = (size_t)argc;

	bool ok = false;

	struct sfdo_basedir_ctx *basedir_ctx = sfdo_basedir_ctx_create();
	if (basedir_ctx == NULL) {
		fprintf(stderr, "sfdo_basedir_ctx_create() failed\n");
		goto err_basedir;
	}

	struct sfdo_icon_ctx *ctx = sfdo_icon_ctx_create(basedir_ctx);
	if (ctx == NULL) {
		fprintf(stderr, "sfdo_icon_ctx_create() failed\n");
		goto err_icon;
	}

	sfdo_icon_ctx_set_log_handler(
			ctx, debug ? SFDO_LOG_LEVEL_DEBUG : SFDO_LOG_LEVEL_ERROR, log_handler, NULL);

	struct sfdo_icon_theme *theme = sfdo_icon_theme_load(ctx, theme_name);
	if (theme == NULL) {
		fprintf(stderr, "Failed to load the icon theme\n");
		goto err_load;
	}

	struct sfdo_icon_file *file =
			sfdo_icon_theme_lookup_best(theme, names, n_names, size, scale, options);
	if (file != NULL) {
		printf("%s\n", sfdo_icon_file_get_path(file, NULL));
	}
	sfdo_icon_file_destroy(file);

	ok = true;

	sfdo_icon_theme_destroy(theme);
err_load:
	sfdo_icon_ctx_destroy(ctx);
err_icon:
	sfdo_basedir_ctx_destroy(basedir_ctx);
err_basedir:
	return ok ? 0 : 1;
}
