#include <assert.h>
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

static void print_str(const char *name, const char *str, size_t str_len) {
	printf("%s: ", name);
	if (str != NULL) {
		printf("%s (%zu bytes)\n", str, str_len);
	} else {
		printf("<unset>\n");
	}
}

static void print_exec(const char *name, struct sfdo_desktop_exec *exec) {
	printf("%s: <", name);
	if (exec != NULL) {
		if (sfdo_desktop_exec_get_has_target(exec)) {
			printf("has target");
			if (sfdo_desktop_exec_get_supports_list(exec)) {
				printf(", supports lists");
			}
			if (sfdo_desktop_exec_get_supports_uri(exec)) {
				printf(", supports URIs");
			}
		} else {
			printf("has no target");
		}
	} else {
		printf("none");
	}
	printf(">\n");
}

static void print_list(const char *name, const struct sfdo_string *strs, size_t n_strs) {
	printf("%s:\n", name);
	for (size_t i = 0; i < n_strs; i++) {
		printf(" %zu: %s (%zu bytes)\n", i, strs[i].data, strs[i].len);
	}
}

static void print_boolean(const char *name, bool value) {
	printf("%s: %s\n", name, value ? "true" : "false");
}

static void die_usage(const char *prog) {
	printf("Usage: %s [-D] [-E environment] [-l locale] <id>\n", prog);
	exit(1);
}

int main(int argc, char **argv) {
	bool debug = false;
	const char *locale = NULL;
	const char *env = NULL;

	char *prog = argv[0];
	int opt;
	while ((opt = getopt(argc, argv, "DE:l:")) != -1) {
		switch (opt) {
		case 'D':
			debug = true;
			break;
		case 'E':
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

	if (argc < 1) {
		die_usage(prog);
	}

	const char *id = argv[0];
	size_t id_len = strlen(id);

	struct sfdo_basedir_ctx *basedir_ctx = sfdo_basedir_ctx_create();
	struct sfdo_desktop_ctx *ctx = sfdo_desktop_ctx_create(basedir_ctx);

	sfdo_desktop_ctx_set_log_handler(
			ctx, debug ? SFDO_LOG_LEVEL_DEBUG : SFDO_LOG_LEVEL_ERROR, log_handler, NULL);

	struct sfdo_desktop_db *db = sfdo_desktop_db_load(ctx, locale);
	if (db == NULL) {
		fprintf(stderr, "Failed to load a database\n");
		return 1;
	}

	struct sfdo_desktop_entry *entry = sfdo_desktop_db_get_entry_by_id(db, id, id_len);
	if (entry != NULL) {
		const char *str;
		size_t str_len;

		const struct sfdo_string *strs;
		size_t n_strs;

		str = sfdo_desktop_entry_get_file_path(entry, &str_len);
		print_str("File path", str, str_len);

		str = sfdo_desktop_entry_get_name(entry, &str_len);
		print_str("Name", str, str_len);
		str = sfdo_desktop_entry_get_generic_name(entry, &str_len);
		print_str("GenericName", str, str_len);
		print_boolean("NoDisplay", sfdo_desktop_entry_get_no_display(entry));
		str = sfdo_desktop_entry_get_comment(entry, &str_len);
		print_str("Comment", str, str_len);
		str = sfdo_desktop_entry_get_icon(entry, &str_len);
		print_str("Icon", str, str_len);

		print_boolean("Shown", sfdo_desktop_entry_show_in(entry, env, SFDO_NT));

		strs = sfdo_desktop_entry_get_implements(entry, &n_strs);
		print_list("Implements", strs, n_strs);

		switch (sfdo_desktop_entry_get_type(entry)) {
		case SFDO_DESKTOP_ENTRY_APPLICATION:
			print_boolean("DBusActivatable", sfdo_desktop_entry_get_dbus_activatable(entry));

			print_exec("Exec", sfdo_desktop_entry_get_exec(entry));

			str = sfdo_desktop_entry_get_try_exec(entry, &str_len);
			print_str("TryExec", str, str_len);
			str = sfdo_desktop_entry_get_path(entry, &str_len);
			print_str("Path", str, str_len);

			print_boolean("Terminal", sfdo_desktop_entry_get_terminal(entry));

			strs = sfdo_desktop_entry_get_mimetypes(entry, &n_strs);
			print_list("MimeType", strs, n_strs);
			strs = sfdo_desktop_entry_get_categories(entry, &n_strs);
			print_list("Categories", strs, n_strs);
			strs = sfdo_desktop_entry_get_keywords(entry, &n_strs);
			print_list("Keywords", strs, n_strs);

			const char *startup_notify;
			switch (sfdo_desktop_entry_get_startup_notify(entry)) {
			case SFDO_DESKTOP_ENTRY_STARTUP_NOTIFY_FALSE:
				startup_notify = "false";
				break;
			case SFDO_DESKTOP_ENTRY_STARTUP_NOTIFY_TRUE:
				startup_notify = "true";
				break;
			case SFDO_DESKTOP_ENTRY_STARTUP_NOTIFY_UNKNOWN:
				startup_notify = "unknown";
				break;
			}
			printf("StartupNotify: %s\n", startup_notify);

			str = sfdo_desktop_entry_get_startup_wm_class(entry, &str_len);
			print_str("StartupWMClass", str, str_len);
			print_boolean(
					"PrefersNonDefaultGPU", sfdo_desktop_entry_get_prefers_non_default_gpu(entry));
			print_boolean("SingleMainWindow", sfdo_desktop_entry_get_single_main_window(entry));

			size_t n_actions;
			struct sfdo_desktop_entry_action **actions =
					sfdo_desktop_entry_get_actions(entry, &n_actions);
			printf("Actions:\n");
			for (size_t i = 0; i < n_actions; i++) {
				struct sfdo_desktop_entry_action *action = actions[i];

				str = sfdo_desktop_entry_action_get_id(action, &str_len);
				assert(str != NULL);
				printf(" %s (%zu bytes):\n", str, str_len);

				str = sfdo_desktop_entry_action_get_name(action, &str_len);
				print_str("  Name", str, str_len);
				str = sfdo_desktop_entry_action_get_icon(action, &str_len);
				print_str("  Icon", str, str_len);

				print_exec("  Exec", sfdo_desktop_entry_action_get_exec(action));
			}

			break;
		case SFDO_DESKTOP_ENTRY_LINK:
			str = sfdo_desktop_entry_get_url(entry, &str_len);
			print_str("URL", str, str_len);
			break;
		case SFDO_DESKTOP_ENTRY_DIRECTORY:
			break;
		}
	}

	sfdo_desktop_db_destroy(db);
	sfdo_desktop_ctx_destroy(ctx);
	sfdo_basedir_ctx_destroy(basedir_ctx);

	return 0;
}
