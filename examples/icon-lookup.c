#include <getopt.h>
#include <sfdo-basedir.h>
#include <sfdo-icon.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define N_NAMES_MAX 16

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
	printf("Usage: %s [-dmrs] <theme> <size> <scale> <names...>\n", prog);
	exit(1);
}

int main(int argc, char **argv) {
	int load_options = SFDO_ICON_THEME_LOAD_OPTIONS_DEFAULT;
	int lookup_options = SFDO_ICON_THEME_LOOKUP_OPTIONS_DEFAULT;
	bool debug = false;

	char *prog = argv[0];
	int opt;
	while ((opt = getopt(argc, argv, "dmrs")) != -1) {
		switch (opt) {
		case 'd':
			debug = true;
			break;
		case 'm':
			load_options |= SFDO_ICON_THEME_LOAD_OPTION_ALLOW_MISSING;
			break;
		case 'r':
			load_options |= SFDO_ICON_THEME_LOAD_OPTION_RELAXED;
			break;
		case 's':
			lookup_options |= SFDO_ICON_THEME_LOOKUP_OPTION_NO_SVG;
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

	size_t n_names = (size_t)argc;
	if (n_names >= N_NAMES_MAX) {
		n_names = N_NAMES_MAX;
	}
	struct sfdo_string names[N_NAMES_MAX];
	for (size_t i = 0; i < n_names; i++) {
		names[i].data = argv[i];
		names[i].len = strlen(argv[i]);
	}

	struct sfdo_basedir_ctx *basedir_ctx = sfdo_basedir_ctx_create();
	if (basedir_ctx == NULL) {
		fprintf(stderr, "sfdo_basedir_ctx_create() failed\n");
		exit(1);
	}

	struct sfdo_icon_ctx *ctx = sfdo_icon_ctx_create(basedir_ctx);
	if (ctx == NULL) {
		fprintf(stderr, "sfdo_icon_ctx_create() failed\n");
		exit(1);
	}

	sfdo_icon_ctx_set_log_handler(
			ctx, debug ? SFDO_LOG_LEVEL_DEBUG : SFDO_LOG_LEVEL_ERROR, log_handler, NULL);

	struct sfdo_icon_theme *theme = sfdo_icon_theme_load(ctx, theme_name, load_options);
	if (theme == NULL) {
		fprintf(stderr, "Failed to load the icon theme\n");
		exit(1);
	}

	bool found = false;

	struct sfdo_icon_file *file =
			sfdo_icon_theme_lookup_best(theme, names, n_names, size, scale, lookup_options);
	if (file == SFDO_ICON_FILE_INVALID) {
		fprintf(stderr, "Failed to look up the icon\n");
		exit(1);
	} else if (file != NULL) {
		printf("%s\n", sfdo_icon_file_get_path(file, NULL));
		found = true;
	}

	sfdo_icon_file_destroy(file);
	sfdo_icon_theme_destroy(theme);
	sfdo_icon_ctx_destroy(ctx);
	sfdo_basedir_ctx_destroy(basedir_ctx);

	return found ? 0 : 1;
}
