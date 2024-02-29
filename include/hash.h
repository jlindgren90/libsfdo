#ifndef HASH_H
#define HASH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct sfdo_hashmap_entry {
	uint32_t hash;
	const char *key; // Borrowed, NULL if empty
};

struct sfdo_hashmap {
	char *mem;
	size_t len, cap;
	size_t entry_size;
};

void sfdo_hashmap_init(struct sfdo_hashmap *map, size_t entry_size);
void sfdo_hashmap_finish(struct sfdo_hashmap *map);

void sfdo_hashmap_clear(struct sfdo_hashmap *map);

// Returns a complete entry if it was found, entry with key == NULL if it was just added,
// NULL otherwise
void *sfdo_hashmap_get(struct sfdo_hashmap *map, const char *key, bool add);

#endif
