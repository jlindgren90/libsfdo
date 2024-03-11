#include <assert.h>
#include <sfdo-desktop-file.h>
#include <sfdo-icon.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "hash.h"
#include "icon.h"
#include "strpool.h"

#define DEFAULT_THEME_NAME "hicolor"
#define INDEX_THEME_PATH "/index.theme"

struct sfdo_icon_scheduled_node {
	const char *name; // Borrowed from theme strings
	size_t name_len;
	struct sfdo_icon_scheduled_node *next;
};

struct sfdo_icon_loader {
	// Per-theme

	struct sfdo_icon_theme *theme;
	struct sfdo_hashmap seen_nodes; // sfdo_hashmap_entry
	struct sfdo_icon_scheduled_node *scheduled_nodes; // Owned
	struct sfdo_icon_scheduled_node *curr_node;

	// Per-node

	char *directories; // Borrowed from theme strings
	char *scaled_directories; // Borrowed from theme strings
	bool seen_icon_theme_group;

	struct sfdo_icon_subdir *subdirs; // Owned, moved into a node after loading
	size_t n_subdirs;
	size_t subdir_i;
	struct sfdo_hashmap subdir_set; // sfdo_hashmap_entry

	// Per-subdir

	int subdir_min_size, subdir_max_size; // For scalable, 0 if not set
	int subdir_threshold; // For threshold
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

	struct sfdo_hashmap_entry *entry = sfdo_hashmap_get(&loader->seen_nodes, name, true);
	if (entry == NULL) {
		logger_write_oom(logger);
		return false;
	} else if (entry->key != NULL) {
		// Already scheduled
		logger_write(logger, SFDO_LOG_LEVEL_DEBUG, "%s already scheduled", name);
		*out = NULL;
		return true;
	}

	char *owned_name = sfdo_strpool_add(&loader->theme->strings, name, name_len);
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

static bool schedule_node_list(struct sfdo_icon_loader *loader, const char *node_list) {
	struct sfdo_icon_scheduled_node *last = loader->curr_node;

	for (const char *p = node_list; p != NULL;) {
		size_t name_len = strcspn(p, ",");
		const char *name = p;
		if (p[name_len] == '\0') {
			p = NULL;
		} else {
			p += name_len + 1;
		}
		if (name_len == 0) {
			continue;
		}

		struct sfdo_icon_scheduled_node *s_node;
		if (!schedule_node(loader, name, name_len, &s_node)) {
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

static bool df_icon_theme_entry_handler(
		const struct sfdo_desktop_file_group_entry *entry, void *data) {
	struct sfdo_icon_loader *loader = data;
	struct sfdo_icon_theme *theme = loader->theme;
	struct sfdo_logger *logger = &theme->ctx->logger;

	if (strcmp(entry->key, "Inherits") == 0) {
		if (!schedule_node_list(loader, entry->value)) {
			return false;
		}
	} else if (strcmp(entry->key, "Directories") == 0) {
		loader->directories = sfdo_strpool_add(&theme->strings, entry->value, entry->value_len);
		if (loader->directories == NULL) {
			logger_write_oom(logger);
			return false;
		}
	} else if (strcmp(entry->key, "ScaledDirectories") == 0) {
		loader->scaled_directories =
				sfdo_strpool_add(&theme->strings, entry->value, entry->value_len);
		if (loader->scaled_directories == NULL) {
			logger_write_oom(logger);
			return false;
		}
	}

	return true;
}

static bool df_icon_theme_end_handler(const struct sfdo_desktop_file_group *group, void *data) {
	struct sfdo_icon_loader *loader = data;
	struct sfdo_logger *logger = &loader->theme->ctx->logger;

	char *directory_list = loader->directories;
	char *scaled_directory_list = loader->scaled_directories;

	if (directory_list == NULL) {
		logger_write(logger, SFDO_LOG_LEVEL_ERROR, "%d:%d: \"Directories\" is unset", group->line,
				group->column);
		return false;
	}

	char *next_list = scaled_directory_list;
	size_t n_subdirs = 0;
	for (char *p = directory_list; p != NULL;) {
		size_t dir_len = strcspn(p, ",");
		char *key = p;
		if (p[dir_len] == '\0') {
			p = next_list;
			next_list = NULL;
		} else {
			p[dir_len] = '\0';
			p += dir_len + 1;
		}
		if (dir_len > 0) {
			struct sfdo_hashmap_entry *entry = sfdo_hashmap_get(&loader->subdir_set, key, true);
			if (entry == NULL) {
				logger_write_oom(logger);
				return false;
			} else if (entry->key != NULL) {
				logger_write(logger, SFDO_LOG_LEVEL_ERROR, "%d:%d: duplicate directory \"%s\"",
						group->line, group->column, key);
				return false;
			}
			entry->key = key;
			++n_subdirs;
		}
	}

	if (n_subdirs > 0) {
		loader->subdirs = calloc(n_subdirs, sizeof(*loader->subdirs));
		if (loader->subdirs == NULL) {
			logger_write_oom(logger);
			return false;
		}
	}
	loader->n_subdirs = n_subdirs;

	return true;
}

static bool df_subdir_entry_handler(const struct sfdo_desktop_file_group_entry *entry, void *data) {
	struct sfdo_icon_loader *loader = data;

	struct sfdo_logger *logger = &loader->theme->ctx->logger;
	struct sfdo_icon_subdir *subdir = &loader->subdirs[loader->subdir_i];

	struct {
		const char *name;
		int *dest;
	} integers[] = {
		{"Size", &subdir->size},
		{"Scale", &subdir->scale},
		{"MinSize", &loader->subdir_min_size},
		{"MaxSize", &loader->subdir_max_size},
		{"Threshold", &loader->subdir_threshold},
	};
	for (size_t i = 0; i < sizeof(integers) / sizeof(*integers); i++) {
		int *dest = integers[i].dest;
		if (strcmp(entry->key, integers[i].name) == 0) {
			*dest = parse_positive_integer(entry->value);
			if (*dest == 0) {
				goto err_value;
			}
			return true;
		}
	}
	if (strcmp(entry->key, "Type") == 0) {
		if (strcmp(entry->value, "Fixed") == 0) {
			subdir->type = SFDO_ICON_SUBDIR_FIXED;
		} else if (strcmp(entry->value, "Scalable") == 0) {
			subdir->type = SFDO_ICON_SUBDIR_SCALABLE;
		} else if (strcmp(entry->value, "Threshold") == 0) {
			subdir->type = SFDO_ICON_SUBDIR_THRESHOLD;
		} else {
			goto err_value;
		}
	}

	return true;

err_value:
	logger_write(logger, SFDO_LOG_LEVEL_ERROR, "%d:%d: invalid %s value \"%s\"", entry->line,
			entry->column, entry->key, entry->value);
	return false;
}

static bool df_subdir_end_handler(const struct sfdo_desktop_file_group *group, void *data) {
	struct sfdo_icon_loader *loader = data;

	struct sfdo_logger *logger = &loader->theme->ctx->logger;

	struct sfdo_icon_subdir *subdir = &loader->subdirs[loader->subdir_i];
	if (subdir->size == 0) {
		logger_write(logger, SFDO_LOG_LEVEL_ERROR, "%d:%d: directory doesn't have a size",
				group->line, group->column);
		return false;
	}
	if (subdir->scale == 0) {
		subdir->scale = 1;
	}

	switch (subdir->type) {
	case SFDO_ICON_SUBDIR_FIXED:
		subdir->min_pixel_size = subdir->max_pixel_size = subdir->size;
		break;
	case SFDO_ICON_SUBDIR_SCALABLE:
		if (loader->subdir_min_size == 0) {
			loader->subdir_min_size = subdir->size;
		}
		if (loader->subdir_max_size == 0) {
			loader->subdir_max_size = subdir->size;
		}
		if (loader->subdir_min_size > loader->subdir_max_size) {
			logger_write(logger, SFDO_LOG_LEVEL_ERROR, "%d:%d: invalid size range: min %d, max %d",
					group->line, group->column, loader->subdir_min_size, loader->subdir_max_size);
		}
		subdir->min_pixel_size = loader->subdir_min_size;
		subdir->max_pixel_size = loader->subdir_max_size;
		break;
	case SFDO_ICON_SUBDIR_UNKNOWN:
		subdir->type = SFDO_ICON_SUBDIR_THRESHOLD;
		// Fallthrough
	case SFDO_ICON_SUBDIR_THRESHOLD:
		if (loader->subdir_threshold == 0) {
			loader->subdir_threshold = 2;
		}
		// SPEC: the specification incorrectly suggests using MinSize/MaxSize for distance
		// calculation even for Threshold subdirectories
		subdir->min_pixel_size = subdir->size - loader->subdir_threshold;
		subdir->max_pixel_size = subdir->size + loader->subdir_threshold;
		break;
	}
	subdir->min_pixel_size *= subdir->scale;
	subdir->max_pixel_size *= subdir->scale;

	assert(loader->subdir_i < loader->n_subdirs);
	++loader->subdir_i;

	return true;
}

static bool df_group_start_handler(const struct sfdo_desktop_file_group *group, void *data,
		sfdo_desktop_file_group_entry_handler_t *out_entry_handler,
		sfdo_desktop_file_group_end_handler_t *out_end_handler) {
	struct sfdo_icon_loader *loader = data;
	struct sfdo_icon_theme *theme = loader->theme;
	struct sfdo_logger *logger = &theme->ctx->logger;

	if (strcmp(group->name, "Icon Theme") == 0) {
		loader->seen_icon_theme_group = true;
		*out_entry_handler = df_icon_theme_entry_handler;
		*out_end_handler = df_icon_theme_end_handler;
		return true;
	}

	if (!loader->seen_icon_theme_group) {
		logger_write(logger, SFDO_LOG_LEVEL_ERROR,
				"%d:%d: expected \"Icon Theme\" group, got \"%s\"", group->line, group->column,
				group->name);
		return false;
	}

	if (strncmp(group->name, "X-", 2) == 0) {
		// Skip all entries
		return true;
	}

	struct sfdo_hashmap_entry *map_entry =
			sfdo_hashmap_get(&loader->subdir_set, group->name, false);
	if (map_entry == NULL) {
		logger_write(logger, SFDO_LOG_LEVEL_ERROR, "%d:%d: unexpected \"%s\" directory group",
				group->line, group->column, group->name);
		return false;
	}

	loader->subdir_min_size = 0;
	loader->subdir_max_size = 0;
	loader->subdir_threshold = 0;

	struct sfdo_icon_subdir *subdir = &loader->subdirs[loader->subdir_i];

	subdir->path.data = map_entry->key;
	subdir->path.len = group->name_len;

	subdir->type = SFDO_ICON_SUBDIR_UNKNOWN;
	subdir->size = 0;
	subdir->scale = 0;

	*out_entry_handler = df_subdir_entry_handler;
	*out_end_handler = df_subdir_end_handler;
	return true;
}

static struct sfdo_icon_theme_node *node_create(const char *name, size_t name_len,
		struct sfdo_icon_subdir *subdirs, size_t n_subdirs, size_t n_basedirs) {
	struct sfdo_icon_theme_node *node = calloc(1, sizeof(*node));
	if (node == NULL) {
		return NULL;
	}

	if (!icon_state_init(&node->state, (n_subdirs + 1) * n_basedirs)) {
		free(node);
		return NULL;
	}

	node->name = name;
	node->name_len = name_len;

	node->subdirs = subdirs;
	node->n_subdirs = n_subdirs;

	return node;
}

static void node_destroy(struct sfdo_icon_theme_node *node) {
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
		logger_write(logger, SFDO_LOG_LEVEL_INFO,
				"Couldn't find an icon theme file for %s, skipping", s_node->name);
		*out = NULL;
		return true;
	}

	loader->curr_node = s_node;

	loader->directories = NULL;
	loader->scaled_directories = NULL;
	loader->seen_icon_theme_group = false;

	loader->subdirs = NULL;
	loader->n_subdirs = 0;
	loader->subdir_i = 0;

	sfdo_hashmap_clear(&loader->subdir_set);

	struct sfdo_desktop_file_error desktop_file_error;
	if (!sfdo_desktop_file_load(fp, &desktop_file_error, NULL, df_group_start_handler, loader)) {
		if (desktop_file_error.code != SFDO_DESKTOP_FILE_ERROR_USER) {
			logger_write(logger, SFDO_LOG_LEVEL_ERROR, "%d:%d: %s", desktop_file_error.line,
					desktop_file_error.column,
					sfdo_desktop_file_error_code_get_description(desktop_file_error.code));
		}
		logger_write(logger, SFDO_LOG_LEVEL_ERROR, "Failed to read the icon theme file for %s",
				s_node->name);
		goto err;
	}

	struct sfdo_icon_theme_node *node = node_create(
			s_node->name, s_node->name_len, loader->subdirs, loader->n_subdirs, theme->n_basedirs);
	if (node == NULL) {
		logger_write_oom(logger);
		goto err;
	}

	*out = node;
	return true;

err:
	free(loader->subdirs);
	return false;
}

static bool load_theme(struct sfdo_icon_theme *theme, const char *name) {
	struct sfdo_icon_loader loader = {
		.theme = theme,
	};
	sfdo_hashmap_init(&loader.seen_nodes, sizeof(struct sfdo_hashmap_entry));
	sfdo_hashmap_init(&loader.subdir_set, sizeof(struct sfdo_hashmap_entry));

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
	sfdo_hashmap_finish(&loader.subdir_set);

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

	theme->ctx = ctx;

	theme->n_basedirs = n_basedirs;
	theme->basedirs = calloc(n_basedirs, sizeof(*theme->basedirs));
	if (theme->basedirs == NULL) {
		goto err_basedirs;
	}

	sfdo_strpool_init(&theme->strings);

	for (size_t i = 0; i < n_basedirs; i++) {
		const struct sfdo_string *src = &basedirs[i];
		struct sfdo_string *dst = &theme->basedirs[i];

		dst->data = sfdo_strpool_add(&theme->strings, src->data, src->len);
		if (dst->data == NULL) {
			goto err_strings;
		}
		dst->len = src->len;
	}

	if (!icon_state_init(&theme->state, n_basedirs)) {
		goto err_icon_state;
	}

	sfdo_strbuild_init(&theme->path_buf);

	return theme;

err_icon_state:
err_strings:
	sfdo_strpool_finish(&theme->strings);
	free(theme->basedirs);
err_basedirs:
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

	if (!load_theme(theme, name)) {
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
	struct sfdo_icon_theme_node *node = theme->nodes;
	while (node != NULL) {
		struct sfdo_icon_theme_node *next = node->next;
		node_destroy(node);
		node = next;
	}

	sfdo_strpool_finish(&theme->strings);
	icon_state_finish(&theme->state);
	sfdo_strbuild_finish(&theme->path_buf);

	free(theme->basedirs);

	free(theme);
}
