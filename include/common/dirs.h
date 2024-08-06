#ifndef COMMON_DIRS_H
#define COMMON_DIRS_H

#include <sfdo-common.h>
#include <stdbool.h>

bool sfdo_dirs_store(const struct sfdo_string *src_dirs, size_t n_src_dirs,
		struct sfdo_string **dst_dirs, size_t *n_dst_dirs, char **dst_mem);

#endif
