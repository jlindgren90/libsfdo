#include <stdint.h>
#include <stdlib.h>

#include "grow.h"

bool sfdo_grow(void *data_ptr, size_t *cap, size_t entry_size) {
	void **data = data_ptr;
	if (*cap > SIZE_MAX / 2 / entry_size) {
		return false;
	}
	size_t new_cap = *cap == 0 ? 256 : *cap * 2;
	void *new_data = realloc(*data, new_cap * entry_size);
	if (new_data == NULL) {
		return false;
	}
	*data = new_data;
	*cap = new_cap;
	return true;
}
