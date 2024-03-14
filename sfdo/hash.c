#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "hash.h"

static uint32_t hash_str(const char *s, size_t len) {
	// FNV-1a, 32 bit
	uint32_t h = 0x811c9dc5;
	for (size_t i = 0; i < len; i++) {
		uint32_t c = (uint32_t)s[i];
		h = (h ^ c) * 0x01000193;
	}
	return h;
}

void sfdo_hashmap_init(struct sfdo_hashmap *map, size_t entry_size) {
	assert(entry_size >= sizeof(struct sfdo_hashmap_entry));
	map->mem = NULL;
	map->len = map->cap = 0;
	map->entry_size = entry_size;
}

void sfdo_hashmap_finish(struct sfdo_hashmap *map) {
	free(map->mem);
}

void sfdo_hashmap_clear(struct sfdo_hashmap *map) {
	free(map->mem);
	map->mem = NULL;
	map->len = map->cap = 0;
}

void *sfdo_hashmap_get(struct sfdo_hashmap *map, const char *key, size_t key_len, bool add) {
	uint32_t hash = hash_str(key, key_len);
	if (map->len > 0) {
		for (size_t i = hash % map->cap;; i = (i + 1) % map->cap) {
			struct sfdo_hashmap_entry *entry =
					(struct sfdo_hashmap_entry *)&map->mem[map->entry_size * i];
			if (entry->key == NULL) {
				break;
			} else if (entry->hash == hash && entry->key_len == key_len &&
					(entry->key == key || memcmp(entry->key, key, key_len) == 0)) {
				return entry;
			}
		}
	}
	if (add) {
		if (map->len * 2 >= map->cap) {
			if (map->cap >= SIZE_MAX / 2 / map->entry_size) {
				return NULL;
			}
			size_t cap = map->cap == 0 ? 256 : map->cap * 2;
			char *mem = calloc(map->entry_size, cap);
			if (mem == NULL) {
				return NULL;
			}
			for (size_t i = 0; i < map->cap; i++) {
				struct sfdo_hashmap_entry *src =
						(struct sfdo_hashmap_entry *)&map->mem[map->entry_size * i];
				if (src->key == NULL) {
					continue;
				}
				for (size_t j = src->hash % cap;; j = (j + 1) % cap) {
					struct sfdo_hashmap_entry *dst =
							(struct sfdo_hashmap_entry *)&mem[map->entry_size * j];
					if (dst->key == NULL) {
						memcpy(dst, src, map->entry_size);
						break;
					}
				}
			}
			free(map->mem);
			map->mem = mem;
			map->cap = cap;
		}
		++map->len;
		for (size_t i = hash % map->cap;; i = (i + 1) % map->cap) {
			struct sfdo_hashmap_entry *entry =
					(struct sfdo_hashmap_entry *)&map->mem[map->entry_size * i];
			if (entry->key == NULL) {
				entry->hash = hash;
				entry->key_len = key_len;
				return entry;
			}
		}
	}
	return NULL;
}
