#include <dirent.h>
#include <sfdo-icon.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "api.h"
#include "grow.h"
#include "icon.h"
#include "strpool.h"

#define ICON_THEME_CACHE_PATH "/icon-theme.cache"

struct sfdo_icon_scanner_image {
	struct sfdo_hashmap_entry base; // sfdo_icon_scanner.image_set
	int formats; // enum sfdo_icon_format_mask
};

static void check_dir_stats(struct sfdo_icon_state *state, size_t dir_i, const char *path) {
	struct stat statbuf;
	if (stat(path, &statbuf) == 0) {
		state->dir_exists[dir_i] = true;
		state->dir_mtimes[dir_i] = statbuf.st_mtime;
	} else {
		state->dir_exists[dir_i] = false;
	}
}

static bool walk_dir(struct sfdo_icon_scanner *scanner, DIR *dirp) {
	struct sfdo_logger *logger = scanner->logger;

	struct dirent *dirent;
	while ((dirent = readdir(dirp)) != NULL) {
		char *name = dirent->d_name;
		size_t name_len = strlen(dirent->d_name);
		if (name_len < 5) {
			continue;
		}
		size_t icon_name_len = name_len - 4;
		if (name[icon_name_len] != '.') {
			continue;
		}

		char *ext = &name[icon_name_len + 1];
		int format = 0;
		if (strcmp(ext, "png") == 0) {
			format = SFDO_ICON_FORMAT_MASK_PNG;
		} else if (strcmp(ext, "svg") == 0) {
			format = SFDO_ICON_FORMAT_MASK_SVG;
		} else if (strcmp(ext, "xpm") == 0) {
			format = SFDO_ICON_FORMAT_MASK_XPM;
		} else {
			continue;
		}

		// Strip extension
		name[icon_name_len] = '\0';

		struct sfdo_icon_scanner_image *entry = sfdo_hashmap_get(&scanner->image_set, name, true);
		if (entry == NULL) {
			logger_write_oom(logger);
			return false;
		} else if (entry->base.key == NULL) {
			entry->base.key = sfdo_strpool_add(&scanner->state.names, name, icon_name_len);
			if (entry->base.key == NULL) {
				logger_write_oom(logger);
				return false;
			}
			entry->formats = 0;
		}
		entry->formats |= format;
	}

	return true;
}

static bool scanner_init(
		struct sfdo_icon_scanner *scanner, struct sfdo_logger *logger, size_t n_dirs) {
	if (!icon_state_init(&scanner->state, n_dirs)) {
		logger_write_oom(logger);
		return false;
	}

	scanner->logger = logger;

	scanner->images_len = scanner->images_cap = 0;
	sfdo_hashmap_init(&scanner->image_set, sizeof(struct sfdo_icon_scanner_image));

	return true;
}

static void scanner_finish(struct sfdo_icon_scanner *scanner) {
	sfdo_hashmap_finish(&scanner->image_set);
}

static void scanner_discard_and_finish(struct sfdo_icon_scanner *scanner) {
	icon_state_finish(&scanner->state);
	scanner_finish(scanner);
}

static void scanner_commit_and_finish(
		struct sfdo_icon_scanner *scanner, struct sfdo_icon_state *out) {
	icon_state_finish(out);
	*out = scanner->state;
	scanner_finish(scanner);
}

bool icon_scanner_add_image(struct sfdo_icon_scanner *scanner, const struct sfdo_string *basedir,
		const struct sfdo_icon_subdir *subdir, const char *name, int formats) {
	struct sfdo_logger *logger = scanner->logger;

	struct sfdo_icon_state *state = &scanner->state;
	if (scanner->images_len == scanner->images_cap &&
			!sfdo_grow(&state->images, &scanner->images_cap, sizeof(*state->images))) {
		logger_write_oom(logger);
		return false;
	}

	struct sfdo_icon_image_list *image_list = sfdo_hashmap_get(&state->map, name, true);
	if (image_list == NULL) {
		logger_write_oom(logger);
		return false;
	} else if (image_list->base.key == NULL) {
		image_list->base.key = name;
		image_list->start_i = scanner->images_len;
	} else {
		state->images[image_list->end_i].next_i = scanner->images_len;
	}

	image_list->end_i = scanner->images_len;
	struct sfdo_icon_image *image = &state->images[scanner->images_len++];

	image->basedir = basedir;
	image->subdir = subdir;
	image->formats = formats;

	image->next_i = (size_t)-1;

	return true;
}

static bool scan_dir(struct sfdo_icon_scanner *scanner, const char *path,
		const struct sfdo_string *basedir, const struct sfdo_icon_subdir *subdir, size_t dir_i) {
	struct sfdo_logger *logger = scanner->logger;

	check_dir_stats(&scanner->state, dir_i, path);

	DIR *dirp = opendir(path);
	if (dirp == NULL) {
		// Nothing to scan
		return true;
	}

	struct sfdo_hashmap *map = &scanner->image_set;
	sfdo_hashmap_clear(map);

	bool walk_ok = walk_dir(scanner, dirp);
	closedir(dirp);

	if (!walk_ok) {
		return false;
	}

	for (size_t i = 0; i < map->cap; i++) {
		struct sfdo_icon_scanner_image *entry = &((struct sfdo_icon_scanner_image *)map->mem)[i];
		if (entry->base.key != NULL) {
			if (!icon_scanner_add_image(
						scanner, basedir, subdir, entry->base.key, entry->formats)) {
				return false;
			}
		}
	}

	logger_write(logger, SFDO_LOG_LEVEL_DEBUG, "Added %zu image(s) from %s", map->len, path);

	return true;
}

static bool rescan_node(struct sfdo_icon_theme_node *node, struct sfdo_icon_theme *theme) {
	struct sfdo_logger *logger = &theme->ctx->logger;

	logger_write(logger, SFDO_LOG_LEVEL_DEBUG, "Scanning %s", node->name);

	struct sfdo_icon_cache **cache_files =
			calloc(theme->n_basedirs, sizeof(struct sfdo_icon_cache *));
	if (cache_files == NULL) {
		logger_write_oom(logger);
		return false;
	}

	struct sfdo_icon_scanner scanner;
	if (!scanner_init(&scanner, logger, theme->n_basedirs * (node->n_subdirs + 1))) {
		logger_write_oom(logger);
		free(cache_files);
		return false;
	}

	bool ok = false;
	struct sfdo_strbuild *pb = &theme->path_buf;

	size_t node_dir_i = 0;
	for (size_t basedir_i = 0; basedir_i < theme->n_basedirs; basedir_i++) {
		struct sfdo_string *basedir = &theme->basedirs[basedir_i];

		sfdo_strbuild_reset(pb);
		if (!sfdo_strbuild_add(pb, basedir->data, basedir->len, node->name, node->name_len, NULL)) {
			logger_write_oom(logger);
			return false;
		}

		check_dir_stats(&scanner.state, node_dir_i++, pb->data);
		if (!scanner.state.dir_exists[basedir_i]) {
			continue;
		}

		if (!sfdo_strbuild_add(
					pb, ICON_THEME_CACHE_PATH, sizeof(ICON_THEME_CACHE_PATH) - 1, NULL)) {
			goto end;
		}
		cache_files[basedir_i] =
				icon_cache_create(pb->data, scanner.state.dir_mtimes[basedir_i], logger);
	}

	for (size_t subdir_i = 0; subdir_i < node->n_subdirs; subdir_i++) {
		struct sfdo_icon_subdir *subdir = &node->subdirs[subdir_i];
		for (size_t basedir_i = 0; basedir_i < theme->n_basedirs; basedir_i++) {
			size_t dir_i = node_dir_i++;

			if (!scanner.state.dir_exists[basedir_i]) {
				// If the /<basedir>/<theme>/ doesn't exist, its subdirs don't exist either
				scanner.state.dir_exists[dir_i] = false;
				continue;
			}

			struct sfdo_string *basedir = &theme->basedirs[basedir_i];

			struct sfdo_icon_cache *cache_file = cache_files[basedir_i];
			if (cache_file != NULL) {
				if (!icon_cache_scan_dir(cache_file, &scanner, basedir, subdir)) {
					goto end;
				}
				continue;
			}

			sfdo_strbuild_reset(pb);
			if (!sfdo_strbuild_add(pb, basedir->data, basedir->len, node->name, node->name_len, "/",
						1, subdir->path.data, subdir->path.len, NULL)) {
				logger_write_oom(logger);
				return false;
			}

			if (!scan_dir(&scanner, pb->data, basedir, subdir, dir_i)) {
				goto end;
			}
		}
	}

	ok = true;

end:
	for (size_t basedir_i = 0; basedir_i < theme->n_basedirs; basedir_i++) {
		struct sfdo_icon_cache *cache_file = cache_files[basedir_i];
		if (cache_file != NULL) {
			icon_cache_destroy(cache_file);
		}
	}
	free(cache_files);

	if (ok) {
		logger_write(logger, SFDO_LOG_LEVEL_INFO, "Found %zu image(s) in %s", scanner.images_len,
				node->name);
		scanner_commit_and_finish(&scanner, &node->state);
		return true;
	} else {
		scanner_discard_and_finish(&scanner);
		return false;
	}
}

static bool rescan_fallback(struct sfdo_icon_theme *theme) {
	struct sfdo_logger *logger = &theme->ctx->logger;

	logger_write(logger, SFDO_LOG_LEVEL_DEBUG, "Scanning fallback icon directories");

	struct sfdo_icon_scanner scanner;
	if (!scanner_init(&scanner, &theme->ctx->logger, theme->n_basedirs)) {
		return false;
	}

	bool ok = false;

	for (size_t basedir_i = 0; basedir_i < theme->n_basedirs; basedir_i++) {
		struct sfdo_string *basedir = &theme->basedirs[basedir_i];
		if (!scan_dir(&scanner, basedir->data, basedir, NULL, basedir_i)) {
			goto end;
		}
	}

	ok = true;

end:
	if (ok) {
		logger_write(
				logger, SFDO_LOG_LEVEL_INFO, "Found %zu fallback image(s)", scanner.images_len);
		scanner_commit_and_finish(&scanner, &theme->state);
		return true;
	} else {
		scanner_discard_and_finish(&scanner);
		return false;
	}
}

static bool rescan_theme(struct sfdo_icon_theme *theme) {
	for (struct sfdo_icon_theme_node *node = theme->nodes; node != NULL; node = node->next) {
		if (!rescan_node(node, theme)) {
			return false;
		}
	}

	if (!rescan_fallback(theme)) {
		return false;
	}

	return true;
}

static bool dir_is_stale(const struct sfdo_icon_state *state, const char *buf, size_t dir_i) {
	bool exists = false;
	time_t mtime;
	struct stat statbuf;
	if (stat(buf, &statbuf) == 0 && S_ISDIR(statbuf.st_mode)) {
		exists = true;
		mtime = statbuf.st_mtime;
	}
	bool c_exists = state->dir_exists[dir_i];
	time_t c_mtime = state->dir_mtimes[dir_i];
	return exists != c_exists || (exists && mtime != c_mtime);
}

static bool node_check_stale(
		struct sfdo_icon_theme_node *node, struct sfdo_icon_theme *theme, bool *out) {
	struct sfdo_logger *logger = &theme->ctx->logger;

	struct sfdo_strbuild *pb = &theme->path_buf;

	size_t node_dir_i = 0;
	for (size_t basedir_i = 0; basedir_i < theme->n_basedirs; basedir_i++) {
		size_t dir_i = node_dir_i++;

		struct sfdo_string *basedir = &theme->basedirs[basedir_i];

		sfdo_strbuild_reset(pb);
		if (!sfdo_strbuild_add(pb, basedir->data, basedir->len, node->name, node->name_len, NULL)) {
			logger_write_oom(logger);
			return false;
		}

		if (dir_is_stale(&node->state, pb->data, dir_i++)) {
			logger_write(logger, SFDO_LOG_LEVEL_DEBUG, "%s is stale", pb->data);
			*out = true;
			return true;
		}
	}

	for (size_t subdir_i = 0; subdir_i < node->n_subdirs; subdir_i++) {
		struct sfdo_icon_subdir *subdir = &node->subdirs[subdir_i];
		for (size_t basedir_i = 0; basedir_i < theme->n_basedirs; basedir_i++) {
			size_t dir_i = node_dir_i++;

			if (!node->state.dir_exists[basedir_i]) {
				// If the /<basedir>/<theme>/ doesn't exist, its subdirs don't exist either
				continue;
			}

			struct sfdo_string *basedir = &theme->basedirs[basedir_i];

			sfdo_strbuild_reset(pb);
			if (!sfdo_strbuild_add(pb, basedir->data, basedir->len, node->name, node->name_len, "/",
						1, subdir->path.data, subdir->path.len, NULL)) {
				logger_write_oom(logger);
				return false;
			}

			if (dir_is_stale(&node->state, pb->data, dir_i)) {
				logger_write(logger, SFDO_LOG_LEVEL_DEBUG, "%s is stale", pb->data);
				*out = true;
				return true;
			}
		}
	}

	*out = false;
	return true;
}

// Returns true on success, false otherwise
bool icon_theme_maybe_rescan(struct sfdo_icon_theme *theme) {
	struct sfdo_logger *logger = &theme->ctx->logger;

	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);

	const struct timespec *then = &theme->scan_time;

	// At least 5 seconds between automatic rescans
	if (now.tv_sec - then->tv_sec - (now.tv_nsec < then->tv_sec) < 5) {
		return true;
	}
	theme->scan_time = now;

	for (size_t basedir_i = 0; basedir_i < theme->n_basedirs; basedir_i++) {
		struct sfdo_string *basedir = &theme->basedirs[basedir_i];
		if (dir_is_stale(&theme->state, basedir->data, basedir_i)) {
			logger_write(logger, SFDO_LOG_LEVEL_DEBUG, "%s is stale", basedir->data);
			return rescan_theme(theme);
		}
	}

	for (struct sfdo_icon_theme_node *node = theme->nodes; node != NULL; node = node->next) {
		bool stale;
		if (!node_check_stale(node, theme, &stale)) {
			return false;
		} else if (stale && !rescan_node(node, theme)) {
			return false;
		}
	}
	return true;
}

SFDO_API bool sfdo_icon_theme_rescan(struct sfdo_icon_theme *theme) {
	clock_gettime(CLOCK_MONOTONIC, &theme->scan_time);
	return rescan_theme(theme);
}
