#ifndef SFDO_DESKTOP_H
#define SFDO_DESKTOP_H

#include <sfdo-common.h>
#include <stdbool.h>

// libsfdo-desktop implements the desktop entry specification:
//
//  https://specifications.freedesktop.org/desktop-entry-spec/desktop-entry-spec-latest.html

struct sfdo_basedir_ctx;

enum sfdo_desktop_entry_type {
	SFDO_DESKTOP_ENTRY_APPLICATION,
	SFDO_DESKTOP_ENTRY_LINK,
	SFDO_DESKTOP_ENTRY_DIRECTORY,
};

enum sfdo_desktop_entry_startup_notify {
	// The application does not work with startup notification at all.
	SFDO_DESKTOP_ENTRY_STARTUP_NOTIFY_FALSE,

	// The application will send a "remove" message when started with the DESKTOP_STARTUP_ID
	// environment variable set.
	SFDO_DESKTOP_ENTRY_STARTUP_NOTIFY_TRUE,

	// The startup notification support status is unknown.
	SFDO_DESKTOP_ENTRY_STARTUP_NOTIFY_UNKNOWN,
};

struct sfdo_desktop_exec;

struct sfdo_desktop_exec_command;

struct sfdo_desktop_ctx;

struct sfdo_desktop_db;

struct sfdo_desktop_entry;

struct sfdo_desktop_entry_action;

// Create a context.
//
// basedir_ctx is used to create the default list of paths which are scanned for desktop entry
// files. basedir_ctx may be NULL, in which case the default list is empty.
//
// Returns NULL on memory allocation error.
struct sfdo_desktop_ctx *sfdo_desktop_ctx_create(struct sfdo_basedir_ctx *basedir_ctx);

// Destroy a context.
//
// ctx may be NULL, in which case the function is no-op.
void sfdo_desktop_ctx_destroy(struct sfdo_desktop_ctx *ctx);

// Set the context log handler.
//
// func will be called for each message with a level lower than or equal to level. func may be NULL.
void sfdo_desktop_ctx_set_log_handler(struct sfdo_desktop_ctx *ctx, enum sfdo_log_level level,
		sfdo_log_handler_func_t func, void *data);

// Load a desktop entry database from the default list of paths.
//
// locale is a string of form lang_COUNTRY.ENCODING@MODIFIER, where _COUNTRY, .ENCODING, and
// @MODIFIER may be omitted. It is used to select the best values for localized strings. May be
// NULL.
//
// Returns NULL on memory allocation error.
struct sfdo_desktop_db *sfdo_desktop_db_load(struct sfdo_desktop_ctx *ctx, const char *locale);

// Load a desktop entry database.
//
// locale is a string of form lang_COUNTRY.ENCODING@MODIFIER, where _COUNTRY, .ENCODING, and
// @MODIFIER may be omitted. It is used to select the best values for localized strings. May be
// NULL.
//
// Returns NULL on memory allocation error.
struct sfdo_desktop_db *sfdo_desktop_db_load_from(struct sfdo_desktop_ctx *ctx, const char *locale,
		const struct sfdo_string *basedirs, size_t n_basedirs);

// Destroy a desktop entry database.
//
// db may be NULL, in which case the function is no-op.
void sfdo_desktop_db_destroy(struct sfdo_desktop_db *db);

// Get a desktop entry by an ID.
//
// If id_len is equal to SFDO_NT, id is assumed to be null-terminated.
//
// Returns NULL if there is no matching desktop entry.
struct sfdo_desktop_entry *sfdo_desktop_db_get_entry_by_id(
		struct sfdo_desktop_db *db, const char *id, size_t id_len);

// Get the list of desktop entries in a database.
//
// The number of entries is saved to n_entries.
struct sfdo_desktop_entry **sfdo_desktop_db_get_entries(
		struct sfdo_desktop_db *db, size_t *n_entries);

// Get the desktop entry type.
enum sfdo_desktop_entry_type sfdo_desktop_entry_get_type(struct sfdo_desktop_entry *entry);

// Get the desktop entry ID.
//
// The length of the ID is saved to len. len may be NULL.
const char *sfdo_desktop_entry_get_id(struct sfdo_desktop_entry *entry, size_t *len);

// Get the desktop entry file path.
//
// The length of the path is saved to len. len may be NULL.
const char *sfdo_desktop_entry_get_file_path(struct sfdo_desktop_entry *entry, size_t *len);

// Get the desktop entry name.
//
// The length of the name is saved to len. len may be NULL.
const char *sfdo_desktop_entry_get_name(struct sfdo_desktop_entry *entry, size_t *len);

// Get the generic desktop entry name.
//
// The length of the name is saved to len. len may be NULL.
//
// Returns NULL if the corresponding key is absent.
const char *sfdo_desktop_entry_get_generic_name(struct sfdo_desktop_entry *entry, size_t *len);

// Returns true if the desktop entry shouldn't be displayed to the user, false otherwise.
bool sfdo_desktop_entry_get_no_display(struct sfdo_desktop_entry *entry);

// Get the desktop entry tooltip.
//
// The length of the tooltip is saved to len. len may be NULL.
//
// Returns NULL if the corresponding key is absent.
const char *sfdo_desktop_entry_get_comment(struct sfdo_desktop_entry *entry, size_t *len);

// Get the desktop entry icon name/path.
//
// The length of the name/path is saved to len. len may be NULL.
//
// Returns NULL if the corresponding key is absent.
const char *sfdo_desktop_entry_get_icon(struct sfdo_desktop_entry *entry, size_t *len);

// env is the desktop environment name. env may be NULL, in which case the default value is
// returned.
//
// If env_len is equal to SFDO_NT and env is not NULL, env is assumed to be null-terminated.
//
// Returns true if the desktop entry should be shown.
bool sfdo_desktop_entry_show_in(struct sfdo_desktop_entry *entry, const char *env, size_t env_len);

// Returns true if D-Bus activation is supported for the application.
//
// The desktop entry type must be "Application".
bool sfdo_desktop_entry_get_dbus_activatable(struct sfdo_desktop_entry *entry);

//
// The desktop entry type must be "Application".
//
// Returns NULL if the corresponding key is absent.
const char *sfdo_desktop_entry_get_try_exec(struct sfdo_desktop_entry *entry, size_t *len);

// Get the application's command template.
//
// The desktop entry type must be "Application".
//
// Returns NULL if the corresponding key is absent.
struct sfdo_desktop_exec *sfdo_desktop_entry_get_exec(struct sfdo_desktop_entry *entry);

// Get the working directory to run the application in.
//
// The desktop entry type must be "Application".
//
// Returns NULL if the corresponding key is absent.
const char *sfdo_desktop_entry_get_path(struct sfdo_desktop_entry *entry, size_t *len);

// Returns true if the application runs in a terminal window, false otherwise.
//
// The desktop entry type must be "Application".
bool sfdo_desktop_entry_get_terminal(struct sfdo_desktop_entry *entry);

// Get the list of application actions.
//
// The desktop entry type must be "Application".
struct sfdo_desktop_entry_action **sfdo_desktop_entry_get_actions(
		struct sfdo_desktop_entry *entry, size_t *n_actions);

// Get the list of MIME types supported by the application.
//
// The desktop entry type must be "Application".
const struct sfdo_string *sfdo_desktop_entry_get_mimetypes(
		struct sfdo_desktop_entry *entry, size_t *n_mimetypes);

// Get the list of categories in which the entry should be shown.
//
// The desktop entry type must be "Application".
const struct sfdo_string *sfdo_desktop_entry_get_categories(
		struct sfdo_desktop_entry *entry, size_t *n_categories);

// Get the list of interfaces the application implements.
//
// The desktop entry type must be "Application".
const struct sfdo_string *sfdo_desktop_entry_get_implements(
		struct sfdo_desktop_entry *entry, size_t *n_implements);

// Get the list of strings which may be used in addition to other metadata to describe the
// application.
//
// The desktop entry type must be "Application".
const struct sfdo_string *sfdo_desktop_entry_get_keywords(
		struct sfdo_desktop_entry *entry, size_t *n_keywords);

// Get the startup notification support status.
//
// The desktop entry type must be "Application".
enum sfdo_desktop_entry_startup_notify sfdo_desktop_entry_get_startup_notify(
		struct sfdo_desktop_entry *entry);

// Get the WM class or WM name hint that the application will map at least one window with.
//
// The desktop entry type must be "Application".
//
// Returns NULL if the corresponding key is absent.
const char *sfdo_desktop_entry_get_startup_wm_class(struct sfdo_desktop_entry *entry, size_t *len);

// Get the URL to access.
//
// The desktop entry type must be "Link".
const char *sfdo_desktop_entry_get_url(struct sfdo_desktop_entry *entry, size_t *len);

// Returns true if the application prefers to be run on a more powerful discrete GPU if available.
//
// The desktop entry type must be "Application".
bool sfdo_desktop_entry_get_prefers_non_default_gpu(struct sfdo_desktop_entry *entry);

// Returns true if the application has a single main window and does not support having an
// additional one opened.
//
// The desktop entry type must be "Application".
bool sfdo_desktop_entry_get_single_main_window(struct sfdo_desktop_entry *entry);

// Get the action ID.
//
// The length of the ID is saved to len. len may be NULL.
const char *sfdo_desktop_entry_action_get_id(struct sfdo_desktop_entry_action *action, size_t *len);

// Get the action name.
//
// The length of the name is saved to len. len may be NULL.
const char *sfdo_desktop_entry_action_get_name(
		struct sfdo_desktop_entry_action *action, size_t *len);

// Get the action icon name/path.
//
// The length of the name/path is saved to len. len may be NULL.
//
// Returns NULL if the corresponding key is absent.
const char *sfdo_desktop_entry_action_get_icon(
		struct sfdo_desktop_entry_action *action, size_t *len);

// Get the action's command template.
//
// Returns NULL if the corresponding key is absent.
struct sfdo_desktop_exec *sfdo_desktop_entry_action_get_exec(
		struct sfdo_desktop_entry_action *action);

// Returns true if the command template has a target, false otherwise.
bool sfdo_desktop_exec_get_has_target(struct sfdo_desktop_exec *exec);

// Returns true if the command template supports using a list of paths as a target, false
// otherwise.
bool sfdo_desktop_exec_get_supports_list(struct sfdo_desktop_exec *exec);

// Returns true if the command template supports using URI(s) as a target, false otherwise.
bool sfdo_desktop_exec_get_supports_uri(struct sfdo_desktop_exec *exec);

// Format a command template with a given path.
//
// Returns NULL on memory allocation error.
struct sfdo_desktop_exec_command *sfdo_desktop_exec_format(
		struct sfdo_desktop_exec *exec, const char *path);

// Format a command template with a given list of paths.
//
// If the command template doesn't support using a list of paths as a target, only the first path
// will be used.
//
// Returns NULL on memory allocation error.
struct sfdo_desktop_exec_command *sfdo_desktop_exec_format_list(
		struct sfdo_desktop_exec *exec, const char **paths, size_t n_paths);

// Get the NULL-terminated list of arguments of the formatted command.
//
// The number of arguments excluding the NULL terminator is saved to n_args. n_args may be NULL.
const char **sfdo_desktop_exec_command_get_args(
		struct sfdo_desktop_exec_command *command, size_t *n_args);

// Destroy a formatted command.
//
// command may be NULL, in which case the function is no-op.
void sfdo_desktop_exec_command_destroy(struct sfdo_desktop_exec_command *command);

#endif
