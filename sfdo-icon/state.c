#include <stdlib.h>

#include "icon.h"
#include "strpool.h"

bool icon_state_init(struct sfdo_icon_state *state, size_t n_dirs) {
	state->dir_mtimes = calloc(n_dirs, sizeof(*state->dir_mtimes));
	state->dir_exists = calloc(n_dirs, sizeof(*state->dir_exists));
	if (state->dir_mtimes == NULL || state->dir_exists == NULL) {
		free(state->dir_mtimes);
		free(state->dir_exists);
		return false;
	}

	sfdo_hashmap_init(&state->map, sizeof(struct sfdo_icon_image_list));
	sfdo_strpool_init(&state->names);
	state->images = NULL;

	return true;
}

void icon_state_finish(struct sfdo_icon_state *state) {
	sfdo_hashmap_finish(&state->map);
	sfdo_strpool_finish(&state->names);
	free(state->images);

	free(state->dir_mtimes);
	free(state->dir_exists);
}
