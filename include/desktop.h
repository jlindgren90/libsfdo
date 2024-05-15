#ifndef DESKTOP_H
#define DESKTOP_H

#include <sfdo-desktop.h>
#include <stddef.h>

#include "hash.h"
#include "log.h"
#include "strpool.h"

struct sfdo_desktop_ctx {
	char *default_basedirs_mem;
	struct sfdo_string *default_basedirs;
	size_t default_n_basedirs;

	struct sfdo_logger logger;
};

enum sfdo_desktop_entry_exec_flags {
	SFDO_DESKTOP_ENTRY_EXEC_SUPPORTS_URI = 1 << 0,
	SFDO_DESKTOP_ENTRY_EXEC_SUPPORTS_LIST = 1 << 1,
	SFDO_DESKTOP_ENTRY_EXEC_EMBED_SINGLE = 1 << 2,
};

struct sfdo_desktop_exec {
	const char **literals; // NULL if unset
	size_t n_literals;
	// If EMBED_SINGLE is set, target_i is the index of a literal the target is embedded into
	// Otherwise, targets are inserted immediately before the literal at target_i
	size_t target_i; // (size_t)-1 if none
	bool supports_uri;
	bool supports_list;
	struct {
		// If and only if (before + after) > 0, the target is embedded and not inserted
		size_t before;
		size_t after;
	} embed;
};

struct sfdo_desktop_entry_action {
	struct sfdo_string id;
	struct sfdo_string name;
	struct sfdo_string icon;
	struct sfdo_desktop_exec exec;
};

struct sfdo_desktop_entry {
	enum sfdo_desktop_entry_type type;

	struct sfdo_string id;
	struct sfdo_string file_path;

	struct sfdo_string name;
	struct sfdo_string generic_name;
	struct sfdo_string comment;
	struct sfdo_string icon;

	struct sfdo_string *implements;
	size_t n_implements;

	struct sfdo_string *show_exceptions;
	size_t n_show_exceptions;

	bool no_display;
	bool default_show;

	union {
		struct {
			struct sfdo_string try_exec;
			struct sfdo_string path;
			struct sfdo_string startup_wm_class;

			struct sfdo_desktop_exec exec;

			struct sfdo_string *mimetypes;
			size_t n_mimetypes;
			struct sfdo_string *categories;
			size_t n_categories;
			struct sfdo_string *keywords;
			size_t n_keywords;

			struct sfdo_desktop_entry_action *actions_mem;
			struct sfdo_desktop_entry_action **actions;
			size_t n_actions;

			enum sfdo_desktop_entry_startup_notify startup_notify;

			// SPEC: not marked as application-only but makes little sense otherwise
			bool dbus_activatable;

			bool terminal;
			bool prefers_non_default_gpu;
			bool single_main_window;
		} app;
		struct {
			struct sfdo_string url;
		} link;
	};
};

struct sfdo_desktop_exec_command {
	const char **args; // Terminated with NULL
	size_t n_args; // Excluding NULL
	char *embedded_mem; // Used for non-standalone %u/%f
};

struct sfdo_desktop_map_entry {
	struct sfdo_hashmap_entry base;
	struct sfdo_desktop_entry *entry; // Owned, may be NULL if deliberately skipped
};

struct sfdo_desktop_db {
	struct sfdo_desktop_ctx *ctx;

	struct sfdo_string *basedirs;
	size_t n_basedirs;
	char *basedirs_mem;

	struct sfdo_strpool strings;
	struct sfdo_hashmap entries; // sfdo_desktop_map_entry

	struct sfdo_desktop_entry **entries_list; // Shared with map entries
	size_t n_entries;
};

#endif
