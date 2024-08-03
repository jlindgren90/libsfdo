#include <stdlib.h>

#include "common/grow.h"

bool sfdo_grow(void *data_ptr, size_t *cap, size_t len, size_t entry_size) {
	return sfdo_grow_n(data_ptr, cap, len, entry_size, 1);
}

bool sfdo_grow_n(void *data_ptr, size_t *cap, size_t len, size_t entry_size, size_t n) {
	size_t new_len = len + n;
	if (new_len < len) {
		// Overflow
		return false;
	} else if (new_len < *cap) {
		return true;
	}

	size_t new_cap = *cap == 0 ? 256 : *cap;
	while (new_cap < new_len) {
		size_t double_cap = new_cap * 2;
		if (double_cap < new_cap) {
			// Overflow
			return false;
		}
		new_cap = double_cap;
	}

	void **data = data_ptr;
	void *new_data = realloc(*data, new_cap * entry_size);
	if (new_data == NULL) {
		return false;
	}

	*data = new_data;
	*cap = new_cap;
	return true;
}
