#include <assert.h>
#include <sfdo-desktop-file.h>
#include <sfdo-icon.h>
#include <stdlib.h>
#include <string.h>

#include "common/api.h"
#include "common/dirs.h"
#include "common/hash.h"
#include "common/striter.h"
#include "common/strpool.h"
#include "sfdo-icon/internal.h"

#define DEFAULT_THEME_NAME "hicolor"
#define INDEX_THEME_PATH "/index.theme"

struct sfdo_icon_scheduled_node {
	const char *name; // Borrowed from theme strings
	size_t name_len;
	struct sfdo_icon_scheduled_node *next;
};

struct sfdo_icon_subdir_group {
	struct sfdo_hashmap_entry base;
	bool seen;
};

struct sfdo_icon_loader {
	struct sfdo_icon_theme *theme;
	struct sfdo_hashmap seen_nodes; // sfdo_hashmap_entry
	struct sfdo_icon_scheduled_node *scheduled_nodes; // Owned
	struct sfdo_icon_scheduled_node *curr_node;

	bool relaxed;
	bool allow_missing;
};

// Returns 0 on error
static int parse_positive_integer(const char *s) {
	int n = 0;
	for (; *s != '\0'; s++) {
		if (*s < '0' || *s > '9') {
			return false;
		}
		// Arbitrary limit such that n² ≤ INT_MAX
		if (n >= 32768) {
			return 0;
		}
		n = n * 10 + *s - '0';
	}
	return n;
}

static bool schedule_node(struct sfdo_icon_loader *loader, const char *name, size_t name_len,
		struct sfdo_icon_scheduled_node **out) {
	struct sfdo_logger *logger = &loader->theme->ctx->logger;

	struct sfdo_hashmap_entry *entry = sfdo_hashmap_get(&loader->seen_nodes, name, name_len, true);
	if (entry == NULL) {
		logger_write_oom(logger);
		return false;
	} else if (entry->key != NULL) {
		// Already scheduled
		logger_write(logger, SFDO_LOG_LEVEL_DEBUG, "%s already scheduled", name);
		*out = NULL;
		return true;
	}

	const char *owned_name = sfdo_strpool_add(&loader->theme->strings, name, name_len);
	if (owned_name == NULL) {
		logger_write_oom(logger);
		return false;
	}

	logger_write(logger, SFDO_LOG_LEVEL_DEBUG, "Scheduling %s", owned_name);

	entry->key = owned_name;

	struct sfdo_icon_scheduled_node *s_node = calloc(1, sizeof(*s_node));
	if (s_node == NULL) {
		logger_write_oom(logger);
		return false;
	}

	s_node->name = owned_name;
	s_node->name_len = name_len;

	*out = s_node;

	return true;
}

static bool schedule_node_list(struct sfdo_icon_loader *loader, const char *list) {
	struct sfdo_icon_scheduled_node *last = loader->curr_node;

	size_t name_start, name_len;
	size_t iter = 0;
	while (sfdo_striter(list, ',', &iter, &name_start, &name_len)) {
		if (name_len == 0) {
			continue;
		}

		struct sfdo_icon_scheduled_node *s_node;
		if (!schedule_node(loader, list + name_start, name_len, &s_node)) {
			return false;
		}

		if (s_node != NULL) {
			s_node->next = last->next;
			last->next = s_node;
			last = s_node;
		}
	}

	return true;
}

static bool add_directory_list(struct sfdo_icon_loader *loader, const char *list,
		struct sfdo_hashmap *subdir_set, int group_line, int group_column) {
	struct sfdo_icon_theme *theme = loader->theme;
	struct sfdo_logger *logger = &theme->ctx->logger;

	size_t dir_start, dir_len;
	size_t iter = 0;
	while (sfdo_striter(list, ',', &iter, &dir_start, &dir_len)) {
		if (dir_len == 0) {
			continue;
		}
		const char *dir = list + dir_start;
		struct sfdo_hashmap_entry *entry = sfdo_hashmap_get(subdir_set, dir, dir_len, true);
		if (entry == NULL) {
			logger_write_oom(logger);
			return false;
		} else if (entry->key != NULL) {
			logger_write(logger, loader->relaxed ? SFDO_LOG_LEVEL_INFO : SFDO_LOG_LEVEL_ERROR,
					"%d:%d: duplicate directory \"%s\"", group_line, group_column, entry->key);
			if (loader->relaxed) {
				continue;
			} else {
				return false;
			}
		}
		entry->key = sfdo_strpool_add(&theme->strings, dir, dir_len);
		if (entry->key == NULL) {
			logger_write_oom(logger);
			return false;
		}
	}

	return true;
}

static struct sfdo_icon_theme_node *node_load(struct sfdo_icon_loader *loader,
		struct sfdo_desktop_file_document *doc, const char *node_name, size_t node_name_len) {
	struct sfdo_icon_theme *theme = loader->theme;
	struct sfdo_logger *logger = &theme->ctx->logger;

	const char *group_name;
	size_t group_name_len;
	int group_line, group_column;

	struct sfdo_desktop_file_entry *entry;
	int entry_line, entry_column;

	const char *value;

	struct sfdo_desktop_file_group *group = sfdo_desktop_file_document_get_groups(doc);
	if (group == NULL) {
		logger_write(logger, SFDO_LOG_LEVEL_ERROR, "Expected \"Icon Theme\" group");
		return NULL;
	}

	sfdo_desktop_file_group_get_location(group, &group_line, &group_column);

	group_name = sfdo_desktop_file_group_get_name(group, &group_name_len);
	if (strcmp(group_name, "Icon Theme") != 0) {
		logger_write(logger, SFDO_LOG_LEVEL_ERROR,
				"%d:%d: expected \"Icon Theme\" group, got \"%s\"", group_line, group_column,
				group_name);
		return NULL;
	}

	if ((entry = sfdo_desktop_file_group_get_entry(group, "Inherits", 8)) != NULL) {
		if (!schedule_node_list(loader, sfdo_desktop_file_entry_get_value(entry, NULL))) {
			return NULL;
		}
	}

	struct sfdo_icon_theme_node *node = NULL;

	struct sfdo_hashmap subdir_set;
	sfdo_hashmap_init(&subdir_set, sizeof(struct sfdo_icon_subdir_group));

	if ((entry = sfdo_desktop_file_group_get_entry(group, "Directories", 11)) != NULL) {
		value = sfdo_desktop_file_entry_get_value(entry, NULL);
		if (!add_directory_list(loader, value, &subdir_set, group_line, group_column)) {
			goto err_initial;
		}
	} else {
		logger_write(logger, SFDO_LOG_LEVEL_ERROR, "%d:%d: Directories is unset", group_line,
				group_column);
		goto err_initial;
	}

	if ((entry = sfdo_desktop_file_group_get_entry(group, "ScaledDirectories", 17)) != NULL) {
		value = sfdo_desktop_file_entry_get_value(entry, NULL);
		if (!add_directory_list(loader, value, &subdir_set, group_line, group_column)) {
			goto err_initial;
		}
	}

	node = calloc(1, sizeof(*node));
	if (node == NULL) {
		logger_write_oom(logger);
		goto err_node;
	}
	node->n_subdirs = subdir_set.len;
	if (node->n_subdirs > 0) {
		node->subdirs = calloc(node->n_subdirs, sizeof(*node->subdirs));
		if (node->subdirs == NULL) {
			logger_write_oom(logger);
			goto err_node_subdirs;
		}
	}

	if (!icon_state_init(&node->state, (node->n_subdirs + 1) * theme->n_basedirs)) {
		logger_write_oom(logger);
		goto err_node_state;
	}

	node->name = node_name;
	node->name_len = node_name_len;

	size_t subdir_i = 0;

	for (group = sfdo_desktop_file_group_get_next(group); group != NULL;
			group = sfdo_desktop_file_group_get_next(group)) {
		group_name = sfdo_desktop_file_group_get_name(group, &group_name_len);
		if (strncmp(group_name, "X-", 2) == 0) {
			// Extension group
			continue;
		}

		struct sfdo_icon_subdir_group *subdir_group =
				sfdo_hashmap_get(&subdir_set, group_name, group_name_len, false);
		if (subdir_group == NULL) {
			// Unknown group
			continue;
		}

		sfdo_desktop_file_group_get_location(group, &group_line, &group_column);

		if (subdir_group->seen) {
			assert(loader->relaxed);
			logger_write(logger, SFDO_LOG_LEVEL_INFO, "%d:%d: duplicate directory group \"%s\"",
					group_line, group_column, group_name);
			continue;
		}

		subdir_group->seen = true;

		assert(subdir_i < node->n_subdirs);
		struct sfdo_icon_subdir *subdir = &node->subdirs[subdir_i++];

		subdir->path.data = subdir_group->base.key;
		subdir->path.len = group_name_len;

		if ((entry = sfdo_desktop_file_group_get_entry(group, "Size", 4)) != NULL) {
			value = sfdo_desktop_file_entry_get_value(entry, NULL);
			if ((subdir->size = parse_positive_integer(value)) == 0) {
				goto err_dir_value;
			}
		} else {
			logger_write(
					logger, SFDO_LOG_LEVEL_ERROR, "%d:%d: Size is unset", group_line, group_column);
			goto err_dir;
		}

		subdir->type = SFDO_ICON_SUBDIR_THRESHOLD;
		if ((entry = sfdo_desktop_file_group_get_entry(group, "Type", 4)) != NULL) {
			value = sfdo_desktop_file_entry_get_value(entry, NULL);
			if (strcmp(value, "Fixed") == 0) {
				subdir->type = SFDO_ICON_SUBDIR_FIXED;
			} else if (strcmp(value, "Scalable") == 0) {
				subdir->type = SFDO_ICON_SUBDIR_SCALABLE;
			} else if (strcmp(value, "Threshold") == 0) {
				subdir->type = SFDO_ICON_SUBDIR_THRESHOLD;
			} else {
				sfdo_desktop_file_entry_get_location(entry, &entry_line, &entry_column);
				logger_write(logger, loader->relaxed ? SFDO_LOG_LEVEL_INFO : SFDO_LOG_LEVEL_ERROR,
						"%d:%d: invalid Type \"%s\"", entry_line, entry_column, value);
				if (!loader->relaxed) {
					goto err_dir;
				}
			}
		}

		if ((entry = sfdo_desktop_file_group_get_entry(group, "Scale", 5)) != NULL) {
			value = sfdo_desktop_file_entry_get_value(entry, NULL);
			if ((subdir->scale = parse_positive_integer(value)) == 0) {
				goto err_dir_value;
			}
		} else {
			subdir->scale = 1;
		}

		subdir->min_pixel_size = subdir->size;
		subdir->max_pixel_size = subdir->size;
		int threshold = 2;

		switch (subdir->type) {
		case SFDO_ICON_SUBDIR_FIXED:
			subdir->min_pixel_size = subdir->max_pixel_size = subdir->size;
			break;
		case SFDO_ICON_SUBDIR_SCALABLE:
			if ((entry = sfdo_desktop_file_group_get_entry(group, "MinSize", 7)) != NULL) {
				value = sfdo_desktop_file_entry_get_value(entry, NULL);
				if ((subdir->min_pixel_size = parse_positive_integer(value)) == 0) {
					goto err_dir_value;
				}
			}
			if ((entry = sfdo_desktop_file_group_get_entry(group, "MaxSize", 7)) != NULL) {
				value = sfdo_desktop_file_entry_get_value(entry, NULL);
				if ((subdir->max_pixel_size = parse_positive_integer(value)) == 0) {
					goto err_dir_value;
				}
			}
			if (subdir->min_pixel_size > subdir->max_pixel_size) {
				logger_write(logger, SFDO_LOG_LEVEL_ERROR,
						"%d:%d: invalid size range: minimum %d, maximum %d", group_line,
						group_column, subdir->min_pixel_size, subdir->max_pixel_size);
				goto err_dir;
			}
			break;
		case SFDO_ICON_SUBDIR_THRESHOLD:
			if ((entry = sfdo_desktop_file_group_get_entry(group, "Threshold", 9)) != NULL) {
				value = sfdo_desktop_file_entry_get_value(entry, NULL);
				if ((threshold = parse_positive_integer(value)) == 0) {
					goto err_dir_value;
				}
			}
			// SPEC: the specification incorrectly suggests using MinSize/MaxSize for distance
			// calculation even for Threshold subdirectories
			subdir->min_pixel_size = subdir->size - threshold;
			subdir->max_pixel_size = subdir->size + threshold;
			break;
		}

		subdir->min_pixel_size *= subdir->scale;
		subdir->max_pixel_size *= subdir->scale;
	}

	if (subdir_i != node->n_subdirs) {
		logger_write(logger, SFDO_LOG_LEVEL_ERROR, "Found only %zu directory groups out of %zu",
				subdir_i, node->n_subdirs);
		goto err_dir;
	}

	goto end;

err_dir_value:
	assert(entry != NULL);
	const char *key = sfdo_desktop_file_entry_get_key(entry, NULL);
	sfdo_desktop_file_entry_get_location(entry, &entry_line, &entry_column);
	logger_write(logger, SFDO_LOG_LEVEL_ERROR, "%d:%d: invalid %s value \"%s\"", entry_line,
			entry_column, key, value);

err_dir:
	icon_state_finish(&node->state);
err_node_state:
	free(node->subdirs);
err_node_subdirs:
	free(node);
err_node:
	node = NULL;
err_initial:
end:
	sfdo_hashmap_finish(&subdir_set);
	return node;
}

static void node_destroy(struct sfdo_icon_theme_node *node) {
	if (node == NULL) {
		return;
	}

	icon_state_finish(&node->state);
	free(node->subdirs);
	free(node);
}

static bool load_node(struct sfdo_icon_loader *loader, struct sfdo_icon_scheduled_node *s_node,
		struct sfdo_icon_theme_node **out) {
	struct sfdo_icon_theme *theme = loader->theme;
	struct sfdo_logger *logger = &theme->ctx->logger;

	logger_write(logger, SFDO_LOG_LEVEL_DEBUG, "Loading %s", s_node->name);

	FILE *fp = NULL;
	struct sfdo_strbuild *pb = &theme->path_buf;

	for (size_t i = 0; i < theme->n_basedirs; i++) {
		const struct sfdo_string *basedir = &theme->basedirs[i];

		sfdo_strbuild_reset(pb);
		if (!sfdo_strbuild_add(pb, basedir->data, basedir->len, s_node->name, s_node->name_len,
					INDEX_THEME_PATH, sizeof(INDEX_THEME_PATH) - 1, NULL)) {
			logger_write_oom(logger);
			return false;
		}

		fp = fopen(pb->data, "r");
		if (fp != NULL) {
			logger_write(logger, SFDO_LOG_LEVEL_DEBUG, "Found an icon theme file %s", pb->data);
			break;
		}
	}

	if (fp == NULL) {
		logger_write(logger, loader->allow_missing ? SFDO_LOG_LEVEL_INFO : SFDO_LOG_LEVEL_ERROR,
				"Couldn't find an icon theme file for %s", s_node->name);
		*out = NULL;
		return loader->allow_missing;
	}

	int df_options = SFDO_DESKTOP_FILE_LOAD_OPTIONS_DEFAULT;
	if (loader->relaxed) {
		df_options |= SFDO_DESKTOP_FILE_LOAD_ALLOW_DUPLICATE_GROUPS;
	}

	struct sfdo_desktop_file_error desktop_file_error;
	struct sfdo_desktop_file_document *doc =
			sfdo_desktop_file_document_load(fp, NULL, df_options, &desktop_file_error);
	fclose(fp);

	if (doc != NULL) {
		struct sfdo_icon_theme_node *node = node_load(loader, doc, s_node->name, s_node->name_len);
		sfdo_desktop_file_document_destroy(doc);
		if (node != NULL) {
			*out = node;
			return true;
		}
	} else {
		logger_write(logger, SFDO_LOG_LEVEL_ERROR, "%d:%d: %s", desktop_file_error.line,
				desktop_file_error.column,
				sfdo_desktop_file_error_code_get_description(desktop_file_error.code));
	}

	logger_write(logger, SFDO_LOG_LEVEL_ERROR, "Failed to load %s", pb->data);
	return false;
}

static bool load_theme(struct sfdo_icon_theme *theme, const char *name, int options) {
	struct sfdo_icon_loader loader = {
		.theme = theme,
		.relaxed = (options & SFDO_ICON_THEME_LOAD_OPTION_RELAXED) != 0,
		.allow_missing = (options & SFDO_ICON_THEME_LOAD_OPTION_ALLOW_MISSING) != 0,
	};
	sfdo_hashmap_init(&loader.seen_nodes, sizeof(struct sfdo_hashmap_entry));

	bool ok = false;

	if (!schedule_node(&loader, name, strlen(name), &loader.scheduled_nodes)) {
		goto end;
	}
	assert(loader.scheduled_nodes != NULL);

	// The default theme is processed last
	if (!schedule_node(&loader, DEFAULT_THEME_NAME, sizeof(DEFAULT_THEME_NAME) - 1,
				&loader.scheduled_nodes->next)) {
		goto end;
	}

	struct sfdo_icon_theme_node **node_ptr = &theme->nodes;

	for (struct sfdo_icon_scheduled_node *s_node = loader.scheduled_nodes; s_node != NULL;
			s_node = s_node->next) {
		loader.curr_node = s_node;

		struct sfdo_icon_theme_node *node;
		if (!load_node(&loader, s_node, &node)) {
			goto end;
		}
		if (node != NULL) {
			*node_ptr = node;
			node_ptr = &node->next;
		}
	}

	ok = true;

end:
	sfdo_hashmap_finish(&loader.seen_nodes);

	struct sfdo_icon_scheduled_node *s_node = loader.scheduled_nodes;
	while (s_node != NULL) {
		struct sfdo_icon_scheduled_node *next = s_node->next;
		free(s_node);
		s_node = next;
	}

	return ok;
}

static struct sfdo_icon_theme *theme_create(
		struct sfdo_icon_ctx *ctx, const struct sfdo_string *basedirs, size_t n_basedirs) {
	struct sfdo_icon_theme *theme = calloc(1, sizeof(*theme));
	if (theme == NULL) {
		goto err_theme;
	}

	if (!sfdo_dirs_store(
				basedirs, n_basedirs, &theme->basedirs, &theme->n_basedirs, &theme->basedirs_mem)) {
		goto err_dirs;
	}

	if (!icon_state_init(&theme->state, n_basedirs)) {
		goto err_icon_state;
	}

	theme->ctx = ctx;

	sfdo_strbuild_init(&theme->path_buf);
	sfdo_strpool_init(&theme->strings);

	return theme;

err_icon_state:
	free(theme->basedirs_mem);
	free(theme->basedirs);
err_dirs:
	free(theme);
err_theme:
	logger_write_oom(&ctx->logger);
	return NULL;
}

SFDO_API struct sfdo_icon_theme *sfdo_icon_theme_load(
		struct sfdo_icon_ctx *ctx, const char *name, int options) {
	return sfdo_icon_theme_load_from(
			ctx, name, ctx->default_basedirs, ctx->default_n_basedirs, options);
}

SFDO_API struct sfdo_icon_theme *sfdo_icon_theme_load_from(struct sfdo_icon_ctx *ctx,
		const char *name, const struct sfdo_string *basedirs, size_t n_basedirs, int options) {
	(void)options;

	struct sfdo_icon_theme *theme = theme_create(ctx, basedirs, n_basedirs);
	if (theme == NULL) {
		return NULL;
	}

	if (name == NULL) {
		name = DEFAULT_THEME_NAME;
	}

	if (!load_theme(theme, name, options)) {
		goto err;
	}
	if (!sfdo_icon_theme_rescan(theme)) {
		goto err;
	}

	return theme;

err:
	sfdo_icon_theme_destroy(theme);
	return NULL;
}

SFDO_API void sfdo_icon_theme_destroy(struct sfdo_icon_theme *theme) {
	if (theme == NULL) {
		return;
	}

	struct sfdo_icon_theme_node *node = theme->nodes;
	while (node != NULL) {
		struct sfdo_icon_theme_node *next = node->next;
		node_destroy(node);
		node = next;
	}

	icon_state_finish(&theme->state);
	sfdo_strbuild_finish(&theme->path_buf);
	sfdo_strpool_finish(&theme->strings);

	free(theme->basedirs_mem);
	free(theme->basedirs);

	free(theme);
}
