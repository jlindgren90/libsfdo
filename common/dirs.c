#include <assert.h>
#include <stdlib.h>

#include "common/dirs.h"
#include "common/membuild.h"
#include "common/path.h"
#include "common/size.h"

bool sfdo_dirs_store(const struct sfdo_string *src_dirs, size_t n_src_dirs,
		struct sfdo_string **dst_dirs, size_t *n_dst_dirs, char **dst_mem) {
	struct sfdo_string *dirs = calloc(n_src_dirs, sizeof(*dirs));

	if (dirs == NULL) {
		return false;
	}

	size_t mem_size = 0;
	for (size_t i = 0; i < n_src_dirs; i++) {
		const struct sfdo_string *dir = &src_dirs[i];
		mem_size += dir->len + 1;
		if (sfdo_path_needs_extra_slash(dir->data, dir->len)) {
			++mem_size;
		}
	}

	struct sfdo_membuild mem_buf;
	if (!sfdo_membuild_setup(&mem_buf, mem_size)) {
		free(dirs);
		return false;
	}

	for (size_t i = 0; i < n_src_dirs; i++) {
		const struct sfdo_string *src = &src_dirs[i];
		struct sfdo_string *dst = &dirs[i];

		dst->data = mem_buf.data + mem_buf.len;
		sfdo_membuild_add(&mem_buf, src->data, src->len, NULL);
		if (sfdo_path_needs_extra_slash(src->data, src->len)) {
			sfdo_membuild_add(&mem_buf, "/", SFDO_SIZE1, NULL);
		}

		dst->len = (size_t)(mem_buf.data + mem_buf.len - dst->data);
		sfdo_membuild_add(&mem_buf, "", SFDO_SIZE1, NULL);
	}
	assert(mem_buf.len == mem_size);

	*dst_dirs = dirs;
	*n_dst_dirs = n_src_dirs;
	*dst_mem = mem_buf.data;

	return true;
}
