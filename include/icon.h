#ifndef ICON_H
#define ICON_H

#include <sfdo-common.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>

#include "hash.h"
#include "log.h"
#include "strbuild.h"
#include "strpool.h"

enum sfdo_icon_format_mask {
	SFDO_ICON_FORMAT_MASK_PNG = (1 << 0),
	SFDO_ICON_FORMAT_MASK_SVG = (1 << 1),
	SFDO_ICON_FORMAT_MASK_XPM = (1 << 2),
};

struct sfdo_icon_ctx {
	char *default_basedirs_mem;
	struct sfdo_string *default_basedirs;
	size_t default_n_basedirs;

	struct sfdo_logger logger;
};

struct sfdo_icon_image {
	const struct sfdo_string *basedir;
	const struct sfdo_icon_subdir *subdir; // NULL if fallback
	int formats; // enum sfdo_icon_format
	size_t next_i; // -1 if last
};

struct sfdo_icon_image_list {
	struct sfdo_hashmap_entry base; // sfdo_icon_state.map
	size_t start_i, end_i;
};

// Can be moved
struct sfdo_icon_state {
	struct sfdo_hashmap map; // sfdo_icon_image_list
	struct sfdo_icon_image *images;
	struct sfdo_strpool names;

	time_t *dir_mtimes;
	bool *dir_exists;
};

enum sfdo_icon_subdir_type {
	SFDO_ICON_SUBDIR_FIXED,
	SFDO_ICON_SUBDIR_SCALABLE,
	SFDO_ICON_SUBDIR_THRESHOLD,
};

struct sfdo_icon_subdir {
	struct sfdo_string path; // Borrowed from theme strings, relative to <basedir>/<theme>
	enum sfdo_icon_subdir_type type;
	int size, scale;
	int min_pixel_size, max_pixel_size;
};

struct sfdo_icon_theme_node {
	const char *name; // Borrowed from theme strings
	size_t name_len;
	struct sfdo_icon_theme_node *next;

	struct sfdo_icon_subdir *subdirs;
	size_t n_subdirs;
	struct sfdo_icon_state state;
};

struct sfdo_icon_theme {
	struct sfdo_icon_ctx *ctx;

	struct sfdo_icon_theme_node *nodes;
	struct sfdo_strpool strings;

	struct sfdo_string *basedirs;
	size_t n_basedirs;
	char *basedirs_mem;

	struct sfdo_icon_state state;

	struct timespec scan_time;
	struct sfdo_strbuild path_buf;
};

struct sfdo_icon_scanner {
	struct sfdo_logger *logger;

	struct sfdo_icon_state state;

	size_t images_len, images_cap;

	struct sfdo_hashmap image_names; // sfdo_hashmap_entry
	struct sfdo_hashmap subdir_image_set; // sfdo_icon_scanner_image
};

bool icon_state_init(struct sfdo_icon_state *state, size_t n_dirs);
void icon_state_finish(struct sfdo_icon_state *state);

struct sfdo_icon_cache *icon_cache_create(
		const char *path, time_t dir_mtime, struct sfdo_logger *logger);
void icon_cache_destroy(struct sfdo_icon_cache *cache);

bool icon_cache_scan_dir(struct sfdo_icon_cache *cache, struct sfdo_icon_scanner *scanner,
		const struct sfdo_string *basedir, const struct sfdo_icon_subdir *subdir);

const char *icon_scanner_intern_name(
		struct sfdo_icon_scanner *scanner, const char *name, size_t name_len);

bool icon_scanner_add_image(struct sfdo_icon_scanner *scanner, const struct sfdo_string *basedir,
		const struct sfdo_icon_subdir *subdir, const char *name, size_t name_len, int formats);

bool icon_theme_maybe_rescan(struct sfdo_icon_theme *theme);

#endif
