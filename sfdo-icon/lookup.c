#include <assert.h>
#include <sfdo-icon.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "icon.h"

#define EXTENSION_LEN 3

struct sfdo_icon_file {
	enum sfdo_icon_file_format format;
	size_t path_len;
	char path[];
};

// SPEC: the algorithm in the specification results in suboptimal matches
static bool curr_is_better(const struct sfdo_icon_image *best, int best_dist,
		const struct sfdo_icon_image *curr, int curr_dist, int size, int scale, int pixel_size) {
	const struct sfdo_icon_subdir *best_dir = best->subdir;
	const struct sfdo_icon_subdir *curr_dir = curr->subdir;

	if (curr_dist == 0) {
		if (best_dist != 0) {
			// Prefer exact over non-exact
			return true;
		}
		// Both are exact matches
	} else {
		// curr isn't an exact match; prefer downscaling
		if (curr_dir->size >= size && best_dir->size < size) {
			return true;
		} else if (curr_dir->size < size && best_dir->size >= size) {
			return false;
		}

		// Both are upscaled or downscaled; prefer closest to exact
		if (curr_dist < best_dist) {
			return true;
		} else if (curr_dist > best_dist) {
			return false;
		}
	}

	// Both are the same distance away from being exact; prefer matching scale
	if (curr_dir->scale == scale && best_dir->scale != scale) {
		return true;
	} else if (curr_dir->scale != scale && best_dir->scale == scale) {
		return false;
	}

	// Both have the same scale; prefer non-scalable
	if (curr_dir->type != SFDO_ICON_SUBDIR_SCALABLE &&
			best_dir->type == SFDO_ICON_SUBDIR_SCALABLE) {
		return true;
	} else if (curr_dir->type == SFDO_ICON_SUBDIR_SCALABLE &&
			best_dir->type != SFDO_ICON_SUBDIR_SCALABLE) {
		return false;
	}

	// Both are scalable or non-scalable; prefer closest to requested pixel size
	return abs(pixel_size - curr_dir->size * curr_dir->scale) <
			abs(pixel_size - best_dir->size * curr_dir->scale);
}

static const struct sfdo_icon_image *node_lookup_icon(struct sfdo_icon_theme_node *node,
		const char *name, int size, int scale, int pixel_size, int formats) {
	struct sfdo_icon_state *state = &node->state;
	struct sfdo_icon_image_list *list = sfdo_hashmap_get(&state->map, name, false);
	if (list == NULL) {
		return NULL;
	}

	const struct sfdo_icon_image *best = NULL;
	int best_dist;
	const struct sfdo_icon_image *img;
	for (size_t i = list->start_i; i != (size_t)-1; i = img->next_i) {
		img = &state->images[i];
		if ((formats & img->formats) == 0) {
			continue;
		}
		const struct sfdo_icon_subdir *subdir = img->subdir;
		if (subdir == NULL) {
			if (best != NULL) {
				return best;
			}
			return img;
		}
		int dist = pixel_size < subdir->min_pixel_size ? subdir->min_pixel_size - pixel_size
				: subdir->max_pixel_size < pixel_size  ? pixel_size - subdir->max_pixel_size
													   : 0;
		if (best == NULL || curr_is_better(best, best_dist, img, dist, size, scale, pixel_size)) {
			best_dist = dist;
			best = img;
		}
	}

	return best;
}

static const struct sfdo_icon_image *theme_lookup_fallback_icon(
		struct sfdo_icon_theme *theme, const char *name, int formats) {
	struct sfdo_icon_state *state = &theme->state;
	struct sfdo_icon_image_list *list = sfdo_hashmap_get(&state->map, name, false);
	if (list == NULL) {
		return NULL;
	}

	const struct sfdo_icon_image *img;
	for (size_t i = list->start_i; i != (size_t)-1; i = img->next_i) {
		img = &state->images[i];
		if ((formats & img->formats) != 0) {
			return img;
		}
	}

	return NULL;
}

SFDO_API struct sfdo_icon_file *sfdo_icon_theme_lookup(
		struct sfdo_icon_theme *theme, const char *name, int size, int scale, int options) {
	return sfdo_icon_theme_lookup_best(theme, &name, 1, size, scale, options);
}

SFDO_API struct sfdo_icon_file *sfdo_icon_theme_lookup_best(struct sfdo_icon_theme *theme,
		const char *const *names, size_t n_names, int size, int scale, int options) {
	struct sfdo_logger *logger = &theme->ctx->logger;

	assert(size > 0);
	assert(scale > 0);

	int pixel_size = size * scale;
	if (pixel_size < 0) {
		return NULL;
	}

	if (!icon_theme_maybe_rescan(theme)) {
		return NULL;
	}

	int formats = SFDO_ICON_FORMAT_MASK_PNG | SFDO_ICON_FORMAT_MASK_XPM;
	if ((options & SFDO_ICON_THEME_LOOKUP_OPTION_NO_SVG) == 0) {
		formats |= SFDO_ICON_FORMAT_MASK_SVG;
	}

	const struct sfdo_icon_image *img = NULL;
	const char *img_name = NULL;

	struct sfdo_icon_theme_node *node;

	for (node = theme->nodes; node != NULL; node = node->next) {
		for (size_t i = 0; i < n_names; i++) {
			const char *name = names[i];
			img = node_lookup_icon(node, name, size, scale, pixel_size, formats);
			if (img != NULL) {
				img_name = name;
				goto found;
			}
		}
	}

	for (size_t i = 0; i < n_names; i++) {
		const char *name = names[i];
		img = theme_lookup_fallback_icon(theme, name, formats);
		if (img != NULL) {
			img_name = name;
			goto found;
		}
	}

	return NULL;

found:
	assert((node == NULL) == (img->subdir == NULL));

	size_t path_len;
	if (node != NULL) {
		// basedir (with slash), node name, slash, subdir, slash, icon name, dot, extension,
		// null terminator
		path_len = img->basedir->len + node->name_len + 1 + img->subdir->path.len + 1 +
				strlen(img_name) + 1 + EXTENSION_LEN + 1;
	} else {
		// basedir (with slash), icon name, dot, extension, null terminator
		path_len = img->basedir->len + strlen(img_name) + 1 + EXTENSION_LEN + 1;
	}

	struct sfdo_icon_file *file = calloc(1, sizeof(*file) + path_len);
	if (file == NULL) {
		logger_write_oom(logger);
		return NULL;
	}

	formats &= img->formats;
	if ((formats & SFDO_ICON_FORMAT_MASK_PNG) != 0) {
		file->format = SFDO_ICON_FILE_FORMAT_PNG;
	} else if ((formats & SFDO_ICON_FORMAT_MASK_SVG) != 0) {
		file->format = SFDO_ICON_FILE_FORMAT_SVG;
	} else if ((formats & SFDO_ICON_FORMAT_MASK_XPM) != 0) {
		file->format = SFDO_ICON_FILE_FORMAT_XPM;
	} else {
		abort(); // Unreachable
	}

	static const char exts[][EXTENSION_LEN + 1] = {
		[SFDO_ICON_FILE_FORMAT_PNG] = "png",
		[SFDO_ICON_FILE_FORMAT_SVG] = "svg",
		[SFDO_ICON_FILE_FORMAT_XPM] = "xpm",
	};

	if (node != NULL) {
		snprintf(file->path, path_len, "%s%s/%s/%s.%s", img->basedir->data, node->name,
				img->subdir->path.data, img_name, exts[file->format]);
	} else {
		snprintf(file->path, path_len, "%s%s.%s", img->basedir->data, img_name, exts[file->format]);
	}

	return file;
}

SFDO_API void sfdo_icon_file_destroy(struct sfdo_icon_file *file) {
	if (file == NULL) {
		return;
	}

	free(file);
}

SFDO_API const char *sfdo_icon_file_get_path(struct sfdo_icon_file *file, size_t *len) {
	if (len != NULL) {
		*len = file->path_len;
	}
	return file->path;
}

SFDO_API enum sfdo_icon_file_format sfdo_icon_file_get_format(struct sfdo_icon_file *file) {
	return file->format;
}
