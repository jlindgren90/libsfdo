#ifndef PATH_H
#define PATH_H

#include <stdbool.h>
#include <stddef.h>

static inline bool sfdo_path_needs_extra_slash(const char *path, size_t len) {
	return len >= 2 && path[len - 1] != '/';
}

#endif
