#include <errno.h>
#include <getopt.h>
#include <sfdo-basedir.h>
#include <sfdo-desktop.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
	printf("Usage: %s [-dp] [-a <action>] <id> [args…]\n", prog);
	exit(1);
}

static struct sfdo_desktop_exec *get_exec(
		struct sfdo_desktop_db *db, const char *id, size_t id_len, const char *action_id) {
	struct sfdo_desktop_entry *entry = sfdo_desktop_db_get_entry_by_id(db, id, id_len);
	if (entry == NULL) {
		fprintf(stderr, "Entry not found\n");
		return NULL;
	} else if (sfdo_desktop_entry_get_type(entry) != SFDO_DESKTOP_ENTRY_APPLICATION) {
		fprintf(stderr, "Not an application\n");
		return NULL;
	}

	struct sfdo_desktop_exec *exec = NULL;
	if (action_id != NULL) {
		size_t n_actions;
		struct sfdo_desktop_entry_action **actions =
				sfdo_desktop_entry_get_actions(entry, &n_actions);
		for (size_t i = 0; i < n_actions; i++) {
			struct sfdo_desktop_entry_action *iter = actions[i];
			const char *iter_id = sfdo_desktop_entry_action_get_id(iter, NULL);
			if (strcmp(iter_id, action_id) == 0) {
				exec = sfdo_desktop_entry_action_get_exec(iter);
				if (exec == NULL) {
					fprintf(stderr, "Action is not executable\n");
					return NULL;
				}
				break;
			}
		}
		if (exec == NULL) {
			fprintf(stderr, "Action not found\n");
		}
	} else {
		exec = sfdo_desktop_entry_get_exec(entry);
		if (exec == NULL) {
			fprintf(stderr, "Application is not executable\n");
			return NULL;
		}
	}

	return exec;
}

int main(int argc, char **argv) {
	bool debug = false;
	const char *action = NULL;
	bool print = false;

	char *prog = argv[0];
	int opt;
	while ((opt = getopt(argc, argv, "dpa:")) != -1) {
		switch (opt) {
		case 'd':
			debug = true;
			break;
		case 'p':
			print = true;
			break;
		case 'a':
			action = optarg;
			break;
		default:
			die_usage(prog);
		}
	}

	argv += optind;
	argc -= optind;

	if (argc < 1) {
		die_usage(prog);
	}

	const char *id = argv[0];
	size_t id_len = strlen(id);

	++argv;
	--argc;

	struct sfdo_basedir_ctx *basedir_ctx = sfdo_basedir_ctx_create();
	struct sfdo_desktop_ctx *ctx = sfdo_desktop_ctx_create(basedir_ctx);

	sfdo_desktop_ctx_set_log_handler(
			ctx, debug ? SFDO_LOG_LEVEL_DEBUG : SFDO_LOG_LEVEL_ERROR, log_handler, NULL);

	struct sfdo_desktop_db *db = sfdo_desktop_db_load(ctx, NULL);
	if (db == NULL) {
		fprintf(stderr, "Failed to load a database\n");
		return 1;
	}

	struct sfdo_desktop_exec *exec = get_exec(db, id, id_len, action);
	if (exec != NULL) {
		struct sfdo_desktop_exec_command *cmd =
				sfdo_desktop_exec_format_list(exec, (const char **)argv, (size_t)argc);
		size_t n_args;
		const char **args = sfdo_desktop_exec_command_get_args(cmd, &n_args);
		if (print) {
			for (size_t i = 0; i < n_args; i++) {
				printf("%zu: %s\n", i + 1, args[i]);
			}
		} else {
			pid_t child = fork();
			if (child == 0) {
				execvp(args[0], (char *const *)args);
				fprintf(stderr, "execvp() failed: %s\n", strerror(errno));
				return 1;
			}
		}
		sfdo_desktop_exec_command_destroy(cmd);
	}

	sfdo_desktop_db_destroy(db);
	sfdo_desktop_ctx_destroy(ctx);
	sfdo_basedir_ctx_destroy(basedir_ctx);

	return 0;
}
