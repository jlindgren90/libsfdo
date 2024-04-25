#ifndef SFDO_DESKTOP_H
#define SFDO_DESKTOP_H

#include <sfdo-common.h>
#include <stdbool.h>

struct sfdo_basedir_ctx;

enum sfdo_desktop_entry_type {
	SFDO_DESKTOP_ENTRY_APPLICATION,
	SFDO_DESKTOP_ENTRY_LINK,
	SFDO_DESKTOP_ENTRY_DIRECTORY,
};

enum sfdo_desktop_entry_startup_notify {
	SFDO_DESKTOP_ENTRY_STARTUP_NOTIFY_FALSE,
	SFDO_DESKTOP_ENTRY_STARTUP_NOTIFY_TRUE,
	SFDO_DESKTOP_ENTRY_STARTUP_NOTIFY_UNKNOWN,
};

struct sfdo_desktop_exec;

struct sfdo_desktop_exec_command;

struct sfdo_desktop_ctx;

struct sfdo_desktop_db;

struct sfdo_desktop_entry;

struct sfdo_desktop_entry_action;

struct sfdo_desktop_ctx *sfdo_desktop_ctx_create(struct sfdo_basedir_ctx *basedir_ctx);

void sfdo_desktop_ctx_destroy(struct sfdo_desktop_ctx *ctx);

void sfdo_desktop_ctx_set_log_handler(struct sfdo_desktop_ctx *ctx, enum sfdo_log_level level,
		sfdo_log_handler_func_t func, void *data);

struct sfdo_desktop_db *sfdo_desktop_db_load(struct sfdo_desktop_ctx *ctx, const char *locale);

struct sfdo_desktop_db *sfdo_desktop_db_load_from(struct sfdo_desktop_ctx *ctx, const char *locale,
		const struct sfdo_string *basedirs, size_t n_basedirs);

void sfdo_desktop_db_destroy(struct sfdo_desktop_db *db);

struct sfdo_desktop_entry *sfdo_desktop_db_get_entry_by_id(
		struct sfdo_desktop_db *db, const char *id, size_t id_len);

enum sfdo_desktop_entry_type sfdo_desktop_entry_get_type(struct sfdo_desktop_entry *entry);

const char *sfdo_desktop_entry_get_file_path(struct sfdo_desktop_entry *entry, size_t *len);

const char *sfdo_desktop_entry_get_name(struct sfdo_desktop_entry *entry, size_t *len);

const char *sfdo_desktop_entry_get_generic_name(struct sfdo_desktop_entry *entry, size_t *len);

bool sfdo_desktop_entry_get_no_display(struct sfdo_desktop_entry *entry);

const char *sfdo_desktop_entry_get_comment(struct sfdo_desktop_entry *entry, size_t *len);

const char *sfdo_desktop_entry_get_icon(struct sfdo_desktop_entry *entry, size_t *len);

bool sfdo_desktop_entry_show_in(struct sfdo_desktop_entry *entry, const char *env, size_t env_len);

bool sfdo_desktop_entry_get_dbus_activatable(struct sfdo_desktop_entry *entry);

const char *sfdo_desktop_entry_get_try_exec(struct sfdo_desktop_entry *entry, size_t *len);

struct sfdo_desktop_exec *sfdo_desktop_entry_get_exec(struct sfdo_desktop_entry *entry);

const char *sfdo_desktop_entry_get_path(struct sfdo_desktop_entry *entry, size_t *len);

bool sfdo_desktop_entry_get_terminal(struct sfdo_desktop_entry *entry);

struct sfdo_desktop_entry_action **sfdo_desktop_entry_get_actions(
		struct sfdo_desktop_entry *entry, size_t *n_actions);

const struct sfdo_string *sfdo_desktop_entry_get_mimetypes(
		struct sfdo_desktop_entry *entry, size_t *n_mimetypes);

const struct sfdo_string *sfdo_desktop_entry_get_categories(
		struct sfdo_desktop_entry *entry, size_t *n_categories);

const struct sfdo_string *sfdo_desktop_entry_get_implements(
		struct sfdo_desktop_entry *entry, size_t *n_implements);

const struct sfdo_string *sfdo_desktop_entry_get_keywords(
		struct sfdo_desktop_entry *entry, size_t *n_keywords);

enum sfdo_desktop_entry_startup_notify sfdo_desktop_entry_get_startup_notify(
		struct sfdo_desktop_entry *entry);

const char *sfdo_desktop_entry_get_startup_wm_class(struct sfdo_desktop_entry *entry, size_t *len);

const char *sfdo_desktop_entry_get_url(struct sfdo_desktop_entry *entry, size_t *len);

bool sfdo_desktop_entry_get_prefers_non_default_gpu(struct sfdo_desktop_entry *entry);

bool sfdo_desktop_entry_get_single_main_window(struct sfdo_desktop_entry *entry);

const char *sfdo_desktop_entry_action_get_id(struct sfdo_desktop_entry_action *action, size_t *len);

const char *sfdo_desktop_entry_action_get_name(
		struct sfdo_desktop_entry_action *action, size_t *len);

const char *sfdo_desktop_entry_action_get_icon(
		struct sfdo_desktop_entry_action *action, size_t *len);

struct sfdo_desktop_exec *sfdo_desktop_entry_action_get_exec(
		struct sfdo_desktop_entry_action *action);

bool sfdo_desktop_exec_get_has_target(struct sfdo_desktop_exec *exec);

bool sfdo_desktop_exec_get_supports_list(struct sfdo_desktop_exec *exec);

bool sfdo_desktop_exec_get_supports_uri(struct sfdo_desktop_exec *exec);

struct sfdo_desktop_exec_command *sfdo_desktop_exec_format(
		struct sfdo_desktop_exec *exec, const char *uri);

struct sfdo_desktop_exec_command *sfdo_desktop_exec_format_list(
		struct sfdo_desktop_exec *exec, const char **uris, size_t n_uris);

const char **sfdo_desktop_exec_command_get_args(
		struct sfdo_desktop_exec_command *command, size_t *n_args);

void sfdo_desktop_exec_command_destroy(struct sfdo_desktop_exec_command *command);

#endif
