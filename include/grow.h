#ifndef GROW_H
#define GROW_H

#include <stdbool.h>
#include <stddef.h>

bool sfdo_grow(void *data_ptr, size_t *cap, size_t entry_size);

#endif
