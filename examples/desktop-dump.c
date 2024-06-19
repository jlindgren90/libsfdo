#include <getopt.h>
#include <sfdo-basedir.h>
#include <sfdo-desktop.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
	printf("Usage: %s [-d] [-e environment] [-l locale]\n", prog);
	exit(1);
}

int main(int argc, char **argv) {
	bool debug = false;
	const char *locale = NULL;
	const char *env = NULL;

	char *prog = argv[0];
	int opt;
	while ((opt = getopt(argc, argv, "de:l:")) != -1) {
		switch (opt) {
		case 'd':
			debug = true;
			break;
		case 'e':
			env = optarg;
			break;
		case 'l':
			locale = optarg;
			break;
		default:
			die_usage(prog);
		}
	}

	argv += optind;
	argc -= optind;

	if (argc > 0) {
		die_usage(prog);
	}

	struct sfdo_basedir_ctx *basedir_ctx = sfdo_basedir_ctx_create();
	struct sfdo_desktop_ctx *ctx = sfdo_desktop_ctx_create(basedir_ctx);

	sfdo_desktop_ctx_set_log_handler(
			ctx, debug ? SFDO_LOG_LEVEL_DEBUG : SFDO_LOG_LEVEL_ERROR, log_handler, NULL);

	struct sfdo_desktop_db *db = sfdo_desktop_db_load(ctx, locale);
	if (db == NULL) {
		fprintf(stderr, "Failed to load a database\n");
		exit(1);
	}

	size_t n_entries;
	struct sfdo_desktop_entry **entries = sfdo_desktop_db_get_entries(db, &n_entries);

	size_t env_len = 0;
	if (env != NULL) {
		env_len = strlen(env);
	}

	for (size_t i = 0; i < n_entries; i++) {
		struct sfdo_desktop_entry *entry = entries[i];
		if (sfdo_desktop_entry_get_no_display(entry)) {
			continue;
		}
		if (!sfdo_desktop_entry_show_in(entry, env, env_len)) {
			continue;
		}
		const char *name = sfdo_desktop_entry_get_name(entry, NULL);
		printf("%s\n", name);
	}

	sfdo_desktop_db_destroy(db);
	sfdo_desktop_ctx_destroy(ctx);
	sfdo_basedir_ctx_destroy(basedir_ctx);

	return 0;
}
