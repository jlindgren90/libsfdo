#include <assert.h>
#include <sfdo-desktop.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "desktop.h"

static const char *unpack_string(struct sfdo_string *string, size_t *len) {
	if (len != NULL) {
		*len = string->len;
	}
	return string->data;
}

SFDO_API enum sfdo_desktop_entry_type sfdo_desktop_entry_get_type(
		struct sfdo_desktop_entry *entry) {
	return entry->type;
}

SFDO_API const char *sfdo_desktop_entry_get_file_path(
		struct sfdo_desktop_entry *entry, size_t *len) {
	return unpack_string(&entry->file_path, len);
}

SFDO_API const char *sfdo_desktop_entry_get_name(struct sfdo_desktop_entry *entry, size_t *len) {
	return unpack_string(&entry->name, len);
}

SFDO_API const char *sfdo_desktop_entry_get_generic_name(
		struct sfdo_desktop_entry *entry, size_t *len) {
	return unpack_string(&entry->generic_name, len);
}

SFDO_API bool sfdo_desktop_entry_get_no_display(struct sfdo_desktop_entry *entry) {
	return entry->no_display;
}

SFDO_API const char *sfdo_desktop_entry_get_comment(struct sfdo_desktop_entry *entry, size_t *len) {
	return unpack_string(&entry->comment, len);
}

SFDO_API const char *sfdo_desktop_entry_get_icon(struct sfdo_desktop_entry *entry, size_t *len) {
	return unpack_string(&entry->icon, len);
}

SFDO_API bool sfdo_desktop_entry_show_in(
		struct sfdo_desktop_entry *entry, const char *env, size_t env_len) {
	if (env != NULL) {
		if (env_len == SFDO_NT) {
			env_len = strlen(env);
		}
		for (size_t i = 0; i < entry->n_show_exceptions; i++) {
			struct sfdo_string *ex = &entry->show_exceptions[i];
			if (ex->len == env_len && memcmp(ex->data, env, env_len) == 0) {
				return !entry->default_show;
			}
		}
	}
	return entry->default_show;
}

SFDO_API bool sfdo_desktop_entry_get_dbus_activatable(struct sfdo_desktop_entry *entry) {
	assert(entry->type == SFDO_DESKTOP_ENTRY_APPLICATION);
	return entry->app.dbus_activatable;
}

SFDO_API const char *sfdo_desktop_entry_get_try_exec(
		struct sfdo_desktop_entry *entry, size_t *len) {
	assert(entry->type == SFDO_DESKTOP_ENTRY_APPLICATION);
	return unpack_string(&entry->app.try_exec, len);
}

SFDO_API struct sfdo_desktop_exec *sfdo_desktop_entry_get_exec(struct sfdo_desktop_entry *entry) {
	assert(entry->type == SFDO_DESKTOP_ENTRY_APPLICATION);
	if (entry->app.exec.literals == NULL) {
		return NULL;
	}
	return &entry->app.exec;
}

SFDO_API const char *sfdo_desktop_entry_get_path(struct sfdo_desktop_entry *entry, size_t *len) {
	assert(entry->type == SFDO_DESKTOP_ENTRY_APPLICATION);
	return unpack_string(&entry->app.path, len);
}

SFDO_API bool sfdo_desktop_entry_get_terminal(struct sfdo_desktop_entry *entry) {
	assert(entry->type == SFDO_DESKTOP_ENTRY_APPLICATION);
	return entry->app.terminal;
}

SFDO_API struct sfdo_desktop_entry_action **sfdo_desktop_entry_get_actions(
		struct sfdo_desktop_entry *entry, size_t *n_actions) {
	assert(entry->type == SFDO_DESKTOP_ENTRY_APPLICATION);
	*n_actions = entry->app.n_actions;
	return entry->app.actions;
}

SFDO_API const struct sfdo_string *sfdo_desktop_entry_get_mimetypes(
		struct sfdo_desktop_entry *entry, size_t *n_mimetypes) {
	assert(entry->type == SFDO_DESKTOP_ENTRY_APPLICATION);
	*n_mimetypes = entry->app.n_mimetypes;
	return entry->app.mimetypes;
}

SFDO_API const struct sfdo_string *sfdo_desktop_entry_get_categories(
		struct sfdo_desktop_entry *entry, size_t *n_categories) {
	assert(entry->type == SFDO_DESKTOP_ENTRY_APPLICATION);
	*n_categories = entry->app.n_categories;
	return entry->app.categories;
}

SFDO_API const struct sfdo_string *sfdo_desktop_entry_get_implements(
		struct sfdo_desktop_entry *entry, size_t *n_implements) {
	*n_implements = entry->n_implements;
	return entry->implements;
}

SFDO_API const struct sfdo_string *sfdo_desktop_entry_get_keywords(
		struct sfdo_desktop_entry *entry, size_t *n_keywords) {
	assert(entry->type == SFDO_DESKTOP_ENTRY_APPLICATION);
	*n_keywords = entry->app.n_keywords;
	return entry->app.keywords;
}

SFDO_API enum sfdo_desktop_entry_startup_notify sfdo_desktop_entry_get_startup_notify(
		struct sfdo_desktop_entry *entry) {
	assert(entry->type == SFDO_DESKTOP_ENTRY_APPLICATION);
	return entry->app.startup_notify;
}

SFDO_API const char *sfdo_desktop_entry_get_startup_wm_class(
		struct sfdo_desktop_entry *entry, size_t *len) {
	assert(entry->type == SFDO_DESKTOP_ENTRY_APPLICATION);
	return unpack_string(&entry->app.startup_wm_class, len);
}

SFDO_API const char *sfdo_desktop_entry_get_url(struct sfdo_desktop_entry *entry, size_t *len) {
	assert(entry->type == SFDO_DESKTOP_ENTRY_LINK);
	return unpack_string(&entry->link.url, len);
}

SFDO_API bool sfdo_desktop_entry_get_prefers_non_default_gpu(struct sfdo_desktop_entry *entry) {
	assert(entry->type == SFDO_DESKTOP_ENTRY_APPLICATION);
	return entry->app.prefers_non_default_gpu;
}

SFDO_API bool sfdo_desktop_entry_get_single_main_window(struct sfdo_desktop_entry *entry) {
	assert(entry->type == SFDO_DESKTOP_ENTRY_APPLICATION);
	return entry->app.single_main_window;
}

SFDO_API const char *sfdo_desktop_entry_action_get_id(
		struct sfdo_desktop_entry_action *action, size_t *len) {
	return unpack_string(&action->id, len);
}

SFDO_API const char *sfdo_desktop_entry_action_get_name(
		struct sfdo_desktop_entry_action *action, size_t *len) {
	return unpack_string(&action->name, len);
}

SFDO_API const char *sfdo_desktop_entry_action_get_icon(
		struct sfdo_desktop_entry_action *action, size_t *len) {
	return unpack_string(&action->icon, len);
}

SFDO_API struct sfdo_desktop_exec *sfdo_desktop_entry_action_get_exec(
		struct sfdo_desktop_entry_action *action) {
	if (action->exec.literals == NULL) {
		return NULL;
	}
	return &action->exec;
}

SFDO_API bool sfdo_desktop_exec_get_has_target(struct sfdo_desktop_exec *exec) {
	return exec->target_i != (size_t)-1;
}

SFDO_API bool sfdo_desktop_exec_get_supports_list(struct sfdo_desktop_exec *exec) {
	return exec->supports_list;
}

SFDO_API bool sfdo_desktop_exec_get_supports_uri(struct sfdo_desktop_exec *exec) {
	return exec->supports_uri;
}

SFDO_API struct sfdo_desktop_exec_command *sfdo_desktop_exec_format(
		struct sfdo_desktop_exec *exec, const char *path) {
	return sfdo_desktop_exec_format_list(exec, &path, 1);
}

SFDO_API struct sfdo_desktop_exec_command *sfdo_desktop_exec_format_list(
		struct sfdo_desktop_exec *exec, const char **paths, size_t n_paths) {
	bool has_target = sfdo_desktop_exec_get_has_target(exec);
	bool embed_single = exec->embed.before > 0 || exec->embed.after > 0;

	size_t n_args = exec->n_literals;
	if (has_target && !embed_single) {
		if (!exec->supports_list && n_paths > 1) {
			// Only use the first target
			n_paths = 1;
		}
		n_args += n_paths;
	}

	struct sfdo_desktop_exec_command *cmd = calloc(1, sizeof(*cmd));
	if (cmd == NULL) {
		goto err_cmd;
	}
	cmd->n_args = n_args;

	// cmd->args[n_args] is NULL
	cmd->args = calloc(sizeof(const char *), n_args + 1);
	if (cmd->args == NULL) {
		goto err_args;
	}

	if (has_target) {
		size_t src_i = 0;
		size_t dst_i = 0;
		while (src_i < exec->target_i) {
			cmd->args[dst_i++] = exec->literals[src_i++];
		}
		if (embed_single && n_paths > 0) {
			const char *embed_src = exec->literals[src_i++];
			const char *uri = paths[0];
			size_t uri_len = strlen(uri);

			cmd->embedded_mem = malloc(exec->embed.before + exec->embed.after + uri_len + 1);
			if (cmd->embedded_mem == NULL) {
				goto err_embedded_mem;
			}

			char *ptr = cmd->embedded_mem;
			memcpy(ptr, embed_src, exec->embed.before);
			ptr += exec->embed.before;
			memcpy(ptr, uri, uri_len);
			ptr += uri_len;
			memcpy(ptr, embed_src + exec->embed.before, exec->embed.after);
			ptr += exec->embed.after;
			*ptr = '\0';

			cmd->args[dst_i++] = cmd->embedded_mem;
		} else {
			for (size_t i = 0; i < n_paths; i++) {
				cmd->args[dst_i++] = paths[i];
			}
		}
		while (src_i < exec->n_literals) {
			cmd->args[dst_i++] = exec->literals[src_i++];
		}
	} else {
		for (size_t i = 0; i < n_args; i++) {
			cmd->args[i] = exec->literals[i];
		}
	}

	return cmd;

err_embedded_mem:
	free(cmd->args);
err_args:
	free(cmd);
err_cmd:
	return NULL;
}

SFDO_API const char **sfdo_desktop_exec_command_get_args(
		struct sfdo_desktop_exec_command *command, size_t *n_args) {
	if (n_args != NULL) {
		*n_args = command->n_args;
	}
	return command->args;
}

SFDO_API void sfdo_desktop_exec_command_destroy(struct sfdo_desktop_exec_command *command) {
	free(command->embedded_mem);
	free(command->args);
	free(command);
}
