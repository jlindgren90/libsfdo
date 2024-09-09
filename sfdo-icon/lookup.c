#include <assert.h>
#include <limits.h>
#include <sfdo-icon.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/api.h"
#include "sfdo-icon/internal.h"

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
			abs(pixel_size - best_dir->size * best_dir->scale);
}

static const struct sfdo_icon_image *node_lookup_icon(struct sfdo_icon_theme_node *node,
		const struct sfdo_string *name, int size, int scale, int pixel_size, int formats) {
	struct sfdo_icon_state *state = &node->state;
	struct sfdo_icon_image_list *list = sfdo_hashmap_get(&state->map, name->data, name->len, false);
	if (list == NULL) {
		return NULL;
	}

	const struct sfdo_icon_image *best = NULL;
	int best_dist = INT_MAX;
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
		struct sfdo_icon_theme *theme, const struct sfdo_string *name, int formats) {
	struct sfdo_icon_state *state = &theme->state;
	struct sfdo_icon_image_list *list = sfdo_hashmap_get(&state->map, name->data, name->len, false);
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

SFDO_API struct sfdo_icon_file *sfdo_icon_theme_lookup(struct sfdo_icon_theme *theme,
		const char *name, size_t name_len, int size, int scale, int options) {
	if (name_len == SFDO_NT) {
		name_len = strlen(name);
	}
	struct sfdo_string name_str = {
		.data = name,
		.len = name_len,
	};
	return sfdo_icon_theme_lookup_best(theme, &name_str, 1, size, scale, options);
}

SFDO_API struct sfdo_icon_file *sfdo_icon_theme_lookup_best(struct sfdo_icon_theme *theme,
		const struct sfdo_string *names, size_t n_names, int size, int scale, int options) {
	struct sfdo_logger *logger = &theme->ctx->logger;

	assert(size > 0);
	assert(scale > 0);

	if ((options & SFDO_ICON_THEME_LOOKUP_OPTION_NO_RESCAN) == 0) {
		if (!icon_theme_maybe_rescan(theme)) {
			return SFDO_ICON_FILE_INVALID;
		}
	}

	int formats = SFDO_ICON_FORMAT_MASK_PNG | SFDO_ICON_FORMAT_MASK_XPM;
	if ((options & SFDO_ICON_THEME_LOOKUP_OPTION_NO_SVG) == 0) {
		formats |= SFDO_ICON_FORMAT_MASK_SVG;
	}

	const struct sfdo_icon_image *img = NULL;
	const struct sfdo_string *img_name = NULL;

	struct sfdo_icon_theme_node *node = NULL;

	int pixel_size = size * scale;

	for (node = theme->nodes; node != NULL; node = node->next) {
		for (size_t i = 0; i < n_names; i++) {
			const struct sfdo_string *name = &names[i];
			img = node_lookup_icon(node, name, size, scale, pixel_size, formats);
			if (img != NULL) {
				img_name = name;
				goto found;
			}
		}
	}

	for (size_t i = 0; i < n_names; i++) {
		const struct sfdo_string *name = &names[i];
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
		// basedir (with slash), node name, slash, subdir, slash, icon name, dot, extension
		path_len = img->basedir->len + node->name_len + 1 + img->subdir->path.len + 1 +
				img_name->len + 1 + EXTENSION_LEN;
	} else {
		// basedir (with slash), icon name, dot, extension
		path_len = img->basedir->len + img_name->len + 1 + EXTENSION_LEN;
	}

	size_t path_size = path_len + 1;

	struct sfdo_icon_file *file = calloc(1, sizeof(*file) + path_size);
	if (file == NULL) {
		logger_write_oom(logger);
		return SFDO_ICON_FILE_INVALID;
	}

	file->path_len = path_len;

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

	const char *ext = NULL;
	switch (file->format) {
	case SFDO_ICON_FILE_FORMAT_PNG:
		ext = "png";
		break;
	case SFDO_ICON_FILE_FORMAT_SVG:
		ext = "svg";
		break;
	case SFDO_ICON_FILE_FORMAT_XPM:
		ext = "xpm";
		break;
	}
	assert(ext != NULL);

	if (node != NULL) {
		snprintf(file->path, path_size, "%s%s/%s/%s.%s", img->basedir->data, node->name,
				img->subdir->path.data, img_name->data, ext);
	} else {
		snprintf(file->path, path_size, "%s%s.%s", img->basedir->data, img_name->data, ext);
	}

	return file;
}

SFDO_API void sfdo_icon_file_destroy(struct sfdo_icon_file *file) {
	if (file == NULL || file == SFDO_ICON_FILE_INVALID) {
		return;
	}

	free(file);
}

SFDO_API const char *sfdo_icon_file_get_path(struct sfdo_icon_file *file, size_t *len) {
	assert(file != NULL && file != SFDO_ICON_FILE_INVALID);
	if (len != NULL) {
		*len = file->path_len;
	}
	return file->path;
}

SFDO_API enum sfdo_icon_file_format sfdo_icon_file_get_format(struct sfdo_icon_file *file) {
	assert(file != NULL && file != SFDO_ICON_FILE_INVALID);
	return file->format;
}
