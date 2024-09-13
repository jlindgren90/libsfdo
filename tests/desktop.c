#include <sfdo-desktop.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void check_value(const char *name, const char *got, size_t got_len, const char *exp) {
	size_t exp_len = strlen(exp);
	if (got_len != exp_len || memcmp(got, exp, exp_len) != 0) {
		fprintf(stderr,
				"\"%s\" value mismatch\n"
				"Expected (length: %zu):\t%s\n"
				"Got      (length: %zu):\t%s\n",
				name, got_len, got, exp_len, exp);
		exit(1);
	}
}

static void check_value_list(
		const char *name, const struct sfdo_string *got, size_t got_len, size_t exp_len, ...) {
	va_list args;
	va_start(args, exp_len);

	struct sfdo_string *exp = calloc(exp_len, sizeof(*exp));
	for (size_t i = 0; i < exp_len; i++) {
		exp[i].data = va_arg(args, const char *);
		exp[i].len = strlen(exp[i].data);
	}

	va_end(args);

	if (got_len != exp_len) {
		goto mismatch;
	}

	for (size_t i = 0; i < exp_len; i++) {
		if (got[i].len != exp[i].len || memcmp(got[i].data, exp[i].data, got[i].len) != 0) {
			goto mismatch;
		}
	}

	free(exp);
	return;

mismatch:
	fprintf(stderr, "\"%s\" value list mismatch\n", name);
	fprintf(stderr, "Expected (length: %zu):\n", exp_len);
	for (size_t i = 0; i < exp_len; i++) {
		fprintf(stderr, "  %zu)\t(length: %zu)\t%s\n", i, exp[i].len, exp[i].data);
	}
	fprintf(stderr, "Got (length: %zu):\n", got_len);
	for (size_t i = 0; i < got_len; i++) {
		fprintf(stderr, "  %zu)\t(length: %zu)\t%s\n", i, got[i].len, got[i].data);
	}

	exit(1);
}

static void check_exec(const char *name, struct sfdo_desktop_exec *exec, size_t exp_len, ...) {
	va_list args;
	va_start(args, exp_len);

	struct sfdo_string *exp = calloc(exp_len, sizeof(*exp));
	for (size_t i = 0; i < exp_len; i++) {
		exp[i].data = va_arg(args, const char *);
		exp[i].len = strlen(exp[i].data);
	}

	const char *targets[64];
	size_t n_targets = 0;
	while ((targets[n_targets] = va_arg(args, const char *)) != NULL) {
		++n_targets;
	}

	va_end(args);

	struct sfdo_desktop_exec_command *command =
			sfdo_desktop_exec_format_list(exec, targets, n_targets);
	size_t got_len;
	const char **got_data = sfdo_desktop_exec_command_get_args(command, &got_len);

	struct sfdo_string *got = calloc(exp_len, sizeof(*got));
	for (size_t i = 0; i < got_len; i++) {
		got[i].data = got_data[i];
		got[i].len = strlen(got_data[i]);
	}

	if (got_len != exp_len) {
		goto mismatch;
	}

	for (size_t i = 0; i < exp_len; i++) {
		if (got[i].len != exp[i].len || memcmp(got[i].data, exp[i].data, got[i].len) != 0) {
			goto mismatch;
		}
	}

	free(exp);
	free(got);
	sfdo_desktop_exec_command_destroy(command);
	return;

mismatch:
	fprintf(stderr, "\"%s\" exec command args mismatch\n", name);
	fprintf(stderr, "Expected (length: %zu):\n", exp_len);
	for (size_t i = 0; i < exp_len; i++) {
		fprintf(stderr, "  %zu)\t(length: %zu)\t%s\n", i, exp[i].len, exp[i].data);
	}
	fprintf(stderr, "Got (length: %zu):\n", got_len);
	for (size_t i = 0; i < got_len; i++) {
		fprintf(stderr, "  %zu)\t(length: %zu)\t%s\n", i, got[i].len, got[i].data);
	}

	exit(1);
}

static struct sfdo_desktop_entry *get_entry(struct sfdo_desktop_db *db, const char *name) {
	struct sfdo_desktop_entry *entry = sfdo_desktop_db_get_entry_by_id(db, name, SFDO_NT);
	if (entry == NULL) {
		fprintf(stderr, "\"%s\" entry not found\n", name);
		exit(1);
	}

	return entry;
}

static void ensure_no_entry(struct sfdo_desktop_db *db, const char *name) {
	struct sfdo_desktop_entry *entry = sfdo_desktop_db_get_entry_by_id(db, name, SFDO_NT);
	if (entry != NULL) {
		fprintf(stderr, "\"%s\" entry unexpectedly found\n", name);
		exit(1);
	}
}

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

int main(void) {
	struct sfdo_desktop_ctx *ctx = sfdo_desktop_ctx_create(NULL);
	sfdo_desktop_ctx_set_log_handler(ctx, SFDO_LOG_LEVEL_DEBUG, log_handler, NULL);

	static const struct sfdo_string basedirs[] = {
		{
			.data = "desktop/basedir1",
			.len = 16,
		},
		{
			.data = "desktop/basedir2",
			.len = 16,
		},
	};
	struct sfdo_desktop_db *db =
			sfdo_desktop_db_load_from(ctx, NULL, basedirs, sizeof(basedirs) / sizeof(*basedirs));

	struct sfdo_desktop_entry *entry;

	const char *value;
	size_t value_len;

	const struct sfdo_string *items;
	size_t n_items;

	struct sfdo_desktop_entry_action *action;
	struct sfdo_desktop_entry_action **actions;
	size_t n_actions;

	// Basic loading

	entry = get_entry(db, "simple");
	if (sfdo_desktop_entry_get_type(entry) != SFDO_DESKTOP_ENTRY_APPLICATION) {
		fprintf(stderr, "simple isn't Application?\n");
		exit(1);
	}
	value = sfdo_desktop_entry_get_name(entry, &value_len);
	check_value("simple name", value, value_len, "simple");
	if (sfdo_desktop_entry_get_startup_notify(entry) != SFDO_DESKTOP_ENTRY_STARTUP_NOTIFY_UNKNOWN) {
		fprintf(stderr, "simple StartupNotify isn't unknown\n");
		exit(1);
	}
	if (!sfdo_desktop_entry_show_in(entry, NULL, SFDO_NT)) {
		fprintf(stderr, "simple is not shown by default\n");
		exit(1);
	}

	// Unusual IDs

	get_entry(db, "com.example.complex");
	get_entry(db, "com-example-nested");
	get_entry(db, "magic");

	// Normal properties

	entry = get_entry(db, "com.example.app-all");
	value = sfdo_desktop_entry_get_name(entry, &value_len);
	check_value("app-all name", value, value_len, "app-all");
	value = sfdo_desktop_entry_get_generic_name(entry, &value_len);
	check_value("app-all generic name", value, value_len, "generic");
	if (!sfdo_desktop_entry_get_no_display(entry)) {
		fprintf(stderr, "app-all NoDisplay is false\n");
		exit(1);
	}
	value = sfdo_desktop_entry_get_comment(entry, &value_len);
	check_value("app-all comment", value, value_len, "comment");
	value = sfdo_desktop_entry_get_icon(entry, &value_len);
	check_value("app-all icon", value, value_len, "icon");
	value = sfdo_desktop_entry_get_try_exec(entry, &value_len);
	check_value("app-all try exec", value, value_len, "/bin/false");
	value = sfdo_desktop_entry_get_path(entry, &value_len);
	check_value("app-all path", value, value_len, "/etc");
	if (!sfdo_desktop_entry_get_terminal(entry)) {
		fprintf(stderr, "app-all Terminal is false\n");
		exit(1);
	}
	items = sfdo_desktop_entry_get_mimetypes(entry, &n_items);
	check_value_list("app-all mimetypes", items, n_items, 2, "foo", "bar");
	items = sfdo_desktop_entry_get_categories(entry, &n_items);
	check_value_list("app-all categories", items, n_items, 3, "Settings", "System", "Utility");
	items = sfdo_desktop_entry_get_keywords(entry, &n_items);
	check_value_list("app-all keywords", items, n_items, 0);
	if (!sfdo_desktop_entry_get_prefers_non_default_gpu(entry)) {
		fprintf(stderr, "app-all PrefersNonDefaultGPU is false\n");
		exit(1);
	}
	if (sfdo_desktop_entry_get_startup_notify(entry) != SFDO_DESKTOP_ENTRY_STARTUP_NOTIFY_TRUE) {
		fprintf(stderr, "simple StartupNotify isn't true\n");
		exit(1);
	}
	if (!sfdo_desktop_entry_get_single_main_window(entry)) {
		fprintf(stderr, "app-all SingleMainWindow is false\n");
		exit(1);
	}

	entry = get_entry(db, "dir");
	if (sfdo_desktop_entry_get_type(entry) != SFDO_DESKTOP_ENTRY_DIRECTORY) {
		fprintf(stderr, "dir isn't Directory?\n");
		exit(1);
	}

	entry = get_entry(db, "link");
	if (sfdo_desktop_entry_get_type(entry) != SFDO_DESKTOP_ENTRY_LINK) {
		fprintf(stderr, "link isn't Link?\n");
		exit(1);
	}
	value = sfdo_desktop_entry_get_url(entry, &value_len);
	check_value("link URL", value, value_len, "https://example.com");

	// ShowIn

	entry = get_entry(db, "only-show-in");
	if (sfdo_desktop_entry_show_in(entry, NULL, SFDO_NT)) {
		fprintf(stderr, "only-show-in is shown by default\n");
		exit(1);
	}
	if (!sfdo_desktop_entry_show_in(entry, "allowed", SFDO_NT)) {
		fprintf(stderr, "only-show-in is not shown by \"allowed\"\n");
		exit(1);
	}

	entry = get_entry(db, "both-show-in");
	if (sfdo_desktop_entry_show_in(entry, NULL, SFDO_NT)) {
		fprintf(stderr, "both-show-in is shown by default\n");
		exit(1);
	}
	if (!sfdo_desktop_entry_show_in(entry, "allowed", SFDO_NT)) {
		fprintf(stderr, "both-show-in is not shown by \"allowed\"\n");
		exit(1);
	}

	entry = get_entry(db, "not-show-in");
	if (!sfdo_desktop_entry_show_in(entry, NULL, SFDO_NT)) {
		fprintf(stderr, "not-show-in is not shown by default\n");
		exit(1);
	}
	if (sfdo_desktop_entry_show_in(entry, "disallowed", SFDO_NT)) {
		fprintf(stderr, "not-show-in is shown by \"disallowed\"\n");
		exit(1);
	}

	// Actions

	entry = get_entry(db, "actions");
	actions = sfdo_desktop_entry_get_actions(entry, &n_actions);
	if (n_actions != 2) {
		fprintf(stderr, "actions has %zu actions\n", n_actions);
		exit(1);
	}

	action = actions[0];
	value = sfdo_desktop_entry_action_get_id(action, &value_len);
	check_value("actions[0] id", value, value_len, "Do Thing");
	value = sfdo_desktop_entry_action_get_name(action, &value_len);
	check_value("actions[0] name", value, value_len, "Do Thing Action");

	action = actions[1];
	value = sfdo_desktop_entry_action_get_id(action, &value_len);
	check_value("actions[1] id", value, value_len, "Sleep");
	value = sfdo_desktop_entry_action_get_name(action, &value_len);
	check_value("actions[1] name", value, value_len, "Sleep Action");

	// Exec

	entry = get_entry(db, "exec-simple");
	check_exec("exec-simple", sfdo_desktop_entry_get_exec(entry), 1, "/bin/sh", NULL);
	check_exec("exec-simple with target", sfdo_desktop_entry_get_exec(entry), 1, "/bin/sh",
			"target", NULL);

	entry = get_entry(db, "exec-complex");
	check_exec("exec-complex", sfdo_desktop_entry_get_exec(entry), 6, "quoted arg$", "--icon",
			"icon", sfdo_desktop_entry_get_name(entry, NULL),
			sfdo_desktop_entry_get_file_path(entry, NULL), "%", NULL);
	check_exec("exec-complex with targets", sfdo_desktop_entry_get_exec(entry), 8, "quoted arg$",
			"--icon", "icon", sfdo_desktop_entry_get_name(entry, NULL),
			sfdo_desktop_entry_get_file_path(entry, NULL), "foo", "bar", "%", "foo", "bar", NULL);

	entry = get_entry(db, "exec-embed");
	char name_buf[64];
	snprintf(name_buf, sizeof(name_buf), "name=%s", sfdo_desktop_entry_get_name(entry, NULL));
	char path_buf[64];
	snprintf(path_buf, sizeof(path_buf), "path=%s", sfdo_desktop_entry_get_file_path(entry, NULL));

	check_exec("exec-embed", sfdo_desktop_entry_get_exec(entry), 5, "/bin/sh", name_buf, path_buf,
			"target=", "deprecated=", NULL);
	check_exec("exec-embed with target", sfdo_desktop_entry_get_exec(entry), 5, "/bin/sh", name_buf,
			path_buf, "target=target", "deprecated=", "target", NULL);

	// DBus

	get_entry(db, "com.example.dbus");

	// Skipped

	ensure_no_entry(db, "hidden");
	ensure_no_entry(db, "unknown-type");

	// Bad entries

	ensure_no_entry(db, "bad-action-duplicate");
	ensure_no_entry(db, "bad-action-no-exec");
	ensure_no_entry(db, "bad-boolean");
	ensure_no_entry(db, "bad-dbus-cont");
	ensure_no_entry(db, "bad-dbus-empty");
	ensure_no_entry(db, "bad-dbus-leader");
	ensure_no_entry(db, "bad-dbus-long");
	ensure_no_entry(db, "bad-dbus-single");
	ensure_no_entry(db, "bad-empty");
	ensure_no_entry(db, "bad-exec-escape");
	ensure_no_entry(db, "bad-exec-field-in-quoted");
	ensure_no_entry(db, "bad-exec-invalid-field");
	ensure_no_entry(db, "bad-exec-multiple-targets");
	ensure_no_entry(db, "bad-exec-no-closing-quote");
	ensure_no_entry(db, "bad-exec-path");
	ensure_no_entry(db, "bad-exec-reserved");
	ensure_no_entry(db, "bad-exec-surrounded-standalone");
	ensure_no_entry(db, "bad-exec-truncated-field");
	ensure_no_entry(db, "bad-exec-unescaped");
	ensure_no_entry(db, "bad-ext");
	ensure_no_entry(db, "bad-group");
	ensure_no_entry(db, "bad-missing-action");
	ensure_no_entry(db, "bad-no-exec");
	ensure_no_entry(db, "bad-no-required");
	ensure_no_entry(db, "bad-show-in-overlap");

	sfdo_desktop_db_destroy(db);
	sfdo_desktop_ctx_destroy(ctx);

	return 0;
}
