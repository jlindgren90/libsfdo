#include <stdlib.h>
#include <string.h>

#include "strpool.h"

struct sfdo_strpool_chunk {
	struct sfdo_strpool_chunk *next;
	char data[];
};

#define CHUNK_MIN_SIZE (4096 - sizeof(struct sfdo_strpool_chunk))

char *sfdo_strpool_add(struct sfdo_strpool *pool, const char *data, size_t len) {
	++len; // Include the null terminator
	char *out = NULL;
	if (len > pool->n_free) {
		size_t data_len = len > CHUNK_MIN_SIZE ? len : CHUNK_MIN_SIZE;

		struct sfdo_strpool_chunk *chunk = malloc(sizeof(*chunk) + data_len);
		if (chunk == NULL) {
			return NULL;
		}
		memcpy(chunk->data, data, len);
		pool->n_free = data_len - len;

		chunk->next = pool->chunks;
		pool->chunks = chunk;

		out = chunk->data;
	} else {
		// If there's free space, the total size is CHUNK_MIN_SIZE
		char *start = pool->chunks->data + CHUNK_MIN_SIZE - pool->n_free;
		memcpy(start, data, len);
		pool->n_free -= len;
		out = start;
	}
	out[len - 1] = '\0';
	return out;
}

void sfdo_strpool_init(struct sfdo_strpool *pool) {
	pool->chunks = NULL;
	pool->n_free = 0;
}

void sfdo_strpool_finish(struct sfdo_strpool *pool) {
	struct sfdo_strpool_chunk *chunk = pool->chunks;
	while (chunk != NULL) {
		struct sfdo_strpool_chunk *next = chunk->next;
		free(chunk);
		chunk = next;
	}
}
