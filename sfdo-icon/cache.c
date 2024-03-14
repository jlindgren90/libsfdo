#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "grow.h"
#include "icon.h"

struct sfdo_icon_cache_image {
	const char *name; // Borrowed from data
	size_t name_len;
	int formats; // enum sfdo_icon_format
	size_t next_i; // -1 if last
};

struct sfdo_icon_cache_dir {
	const char *name; // Borrowed from data
	size_t name_len;
	size_t start_i, end_i;
};

struct sfdo_icon_cache {
	char *data; // mmap'ed
	size_t size;
	struct sfdo_icon_cache_dir *dirs;
	size_t n_dirs;
	struct sfdo_icon_cache_image *images;
};

static inline bool read_card16(struct sfdo_icon_cache *cache, size_t offset, uint16_t *out) {
	if (offset + 2 > cache->size) {
		return false;
	}
	*out = htons(*(uint16_t *)(cache->data + offset));
	return true;
}

static inline bool read_card32(struct sfdo_icon_cache *cache, size_t offset, uint32_t *out) {
	if (offset + 4 > cache->size) {
		return false;
	}
	*out = htonl(*(uint32_t *)(cache->data + offset));
	return true;
}

static inline bool read_str(
		struct sfdo_icon_cache *cache, size_t offset, const char **out, size_t *out_len) {
	size_t limit = cache->size - offset;
	*out = cache->data + offset;
	*out_len = strnlen(*out, limit);
	return *out_len < limit;
}

static bool load_cache(struct sfdo_icon_cache *cache, struct sfdo_logger *logger) {
	uint16_t major, minor;
	if (!read_card16(cache, 0, &major) || !read_card16(cache, 2, &minor)) {
		goto err_format;
	}

	if (major != 1 || minor != 0) {
		logger_write(logger, SFDO_LOG_LEVEL_INFO, "Expected version 1.0, got, %d.%d", major, minor);
		return false;
	}

	uint32_t hash_off, dir_list_off;
	if (!read_card32(cache, 4, &hash_off) || !read_card32(cache, 8, &dir_list_off)) {
		goto err_format;
	}

	uint32_t n_dirs;
	if (!read_card32(cache, dir_list_off, &n_dirs)) {
		goto err_format;
	}

	cache->n_dirs = n_dirs;
	cache->dirs = calloc(n_dirs, sizeof(*cache->dirs));
	if (cache->dirs == NULL) {
		logger_write_oom(logger);
		return false;
	}

	for (uint32_t i = 0; i < n_dirs; i++) {
		uint32_t dir_off;
		if (!read_card32(cache, dir_list_off + 4 * (1 + i), &dir_off)) {
			goto err_format;
		}
		struct sfdo_icon_cache_dir *dir = &cache->dirs[i];
		if (!read_str(cache, dir_off, &dir->name, &dir->name_len)) {
			goto err_format;
		}
		dir->start_i = (size_t)-1;
	}

	size_t images_len = 0, images_cap = 0;

	uint32_t n_buckets;
	if (!read_card32(cache, hash_off, &n_buckets)) {
		goto err_format;
	}
	for (uint32_t i = 0; i < n_buckets; i++) {
		uint32_t icon_off;
		if (!read_card32(cache, hash_off + 4 + 4 * i, &icon_off)) {
			goto err_format;
		};
		while (icon_off != 0xFFFFFFFF) {
			uint32_t chain_off, name_off, image_list_off;
			if (!read_card32(cache, icon_off, &chain_off) ||
					!read_card32(cache, icon_off + 4, &name_off) ||
					!read_card32(cache, icon_off + 8, &image_list_off)) {
				goto err_format;
			}

			const char *name;
			size_t name_len;
			if (!read_str(cache, name_off, &name, &name_len)) {
				goto err_format;
			}

			uint32_t n_images;
			if (!read_card32(cache, image_list_off, &n_images)) {
				goto err_format;
			}
			for (uint32_t j = 0; j < n_images; j++) {
				uint32_t image_off = image_list_off + 4 + 8 * j;
				uint16_t dir_i, flags;
				if (!read_card16(cache, image_off, &dir_i) ||
						!read_card16(cache, image_off + 2, &flags)) {
					goto err_format;
				}

				if (dir_i >= n_dirs) {
					goto err_format;
				}

				if (images_len == images_cap &&
						!sfdo_grow(&cache->images, &images_cap, sizeof(*cache->images))) {
					logger_write_oom(logger);
					return false;
				}

				struct sfdo_icon_cache_dir *dir = &cache->dirs[dir_i];
				if (dir->start_i == (size_t)-1) {
					dir->start_i = images_len;
				} else {
					cache->images[dir->end_i].next_i = images_len;
				}

				dir->end_i = images_len;
				struct sfdo_icon_cache_image *image = &cache->images[images_len++];

				image->name = name;
				image->name_len = name_len;

				image->formats = 0;
				if ((flags & 0x1) != 0) {
					image->formats |= SFDO_ICON_FORMAT_MASK_XPM;
				}
				if ((flags & 0x2) != 0) {
					image->formats |= SFDO_ICON_FORMAT_MASK_SVG;
				}
				if ((flags & 0x4) != 0) {
					image->formats |= SFDO_ICON_FORMAT_MASK_PNG;
				}

				image->next_i = (size_t)-1;
			}

			icon_off = chain_off;
		}
	}

	logger_write(logger, SFDO_LOG_LEVEL_DEBUG, "Found %zu cached image(s)", images_len);
	return true;

err_format:
	logger_write(logger, SFDO_LOG_LEVEL_INFO, "Invalid icon-theme.cache format");
	return false;
}

struct sfdo_icon_cache *icon_cache_create(
		const char *path, time_t dir_mtime, struct sfdo_logger *logger) {
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		goto err_fd;
	}

	logger_write(logger, SFDO_LOG_LEVEL_DEBUG, "Found cache file %s", path);

	struct stat statbuf;
	if (fstat(fd, &statbuf) != 0 || !S_ISREG(statbuf.st_mode)) {
		goto err_stat;
	}

	if (statbuf.st_mtime < dir_mtime) {
		logger_write(logger, SFDO_LOG_LEVEL_DEBUG, "Too old: file mtime %ld, dir mtime %ld",
				(long)statbuf.st_mtime, (long)dir_mtime);
		goto err_stat;
	}

	size_t size = (size_t)statbuf.st_size;
	char *data = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
	close(fd);

	if (data == MAP_FAILED) {
		logger_write(
				logger, SFDO_LOG_LEVEL_ERROR, "Failed to mmap() %s: %s", path, strerror(errno));
		return NULL;
	}

	struct sfdo_icon_cache *cache = calloc(1, sizeof(*cache));
	if (cache == NULL) {
		logger_write_oom(logger);
		munmap(data, size);
		return NULL;
	}

	cache->data = data;
	cache->size = size;

	if (!load_cache(cache, logger)) {
		logger_write(logger, SFDO_LOG_LEVEL_INFO, "Failed to load, ignoring");
		icon_cache_destroy(cache);
		return NULL;
	}

	return cache;

err_stat:
	close(fd);
err_fd:
	return NULL;
}

void icon_cache_destroy(struct sfdo_icon_cache *cache) {
	munmap(cache->data, cache->size);
	free(cache->dirs);
	free(cache->images);
	free(cache);
}

bool icon_cache_scan_dir(struct sfdo_icon_cache *cache, struct sfdo_icon_scanner *scanner,
		const struct sfdo_string *basedir, const struct sfdo_icon_subdir *subdir) {
	struct sfdo_logger *logger = scanner->logger;

	assert(subdir != NULL);
	const char *subdir_data = subdir->path.data;

	struct sfdo_icon_cache_dir *dir = NULL;
	for (size_t i = 0; i < cache->n_dirs; i++) {
		struct sfdo_icon_cache_dir *curr = &cache->dirs[i];
		if (subdir->path.len == curr->name_len &&
				memcmp(subdir_data, curr->name, curr->name_len) == 0) {
			dir = curr;
			break;
		}
	}
	if (dir == NULL) {
		return true;
	}

	size_t n_images = 0;
	struct sfdo_icon_cache_image *image;
	for (size_t i = dir->start_i; i != (size_t)-1; i = image->next_i) {
		image = &cache->images[i];
		const char *name = icon_scanner_intern_name(scanner, image->name, image->name_len);
		if (name == NULL) {
			return false;
		}
		if (!icon_scanner_add_image(
					scanner, basedir, subdir, name, image->name_len, image->formats)) {
			return false;
		}
		++n_images;
	}
	logger_write(logger, SFDO_LOG_LEVEL_DEBUG, "Added %zu cached image(s) for %s in %s", n_images,
			subdir_data, basedir->data);

	return true;
}
