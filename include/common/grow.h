#ifndef GROW_H
#define GROW_H

#include <stdbool.h>
#include <stddef.h>

bool sfdo_grow(void *data_ptr, size_t *cap, size_t len, size_t entry_size);

bool sfdo_grow_n(void *data_ptr, size_t *cap, size_t len, size_t entry_size, size_t n);

#endif
