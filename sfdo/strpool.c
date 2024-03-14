#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "strpool.h"

struct sfdo_strpool_chunk {
	struct sfdo_strpool_chunk *next;
	char data[];
};

#define CHUNK_MIN_SIZE (4096 - sizeof(struct sfdo_strpool_chunk) - 8)

char *sfdo_strpool_add(struct sfdo_strpool *pool, const char *data, size_t len) {
	++len; // Include the null terminator
	char *out = NULL;
	if (len > pool->n_free) {
		size_t data_size = len > CHUNK_MIN_SIZE ? len : CHUNK_MIN_SIZE;

		struct sfdo_strpool_chunk *chunk = malloc(sizeof(*chunk) + data_size);
		if (chunk == NULL) {
			return NULL;
		}

		size_t chunk_nfree = data_size - len;
		if (chunk_nfree < pool->n_free) {
			// Put the new chunk after head
			assert(pool->chunks != NULL);
			chunk->next = pool->chunks->next;
			pool->chunks->next = chunk;
		} else {
			// The new chunk is the new head
			chunk->next = pool->chunks;
			pool->chunks = chunk;
			pool->n_free = chunk_nfree;
		}

		out = chunk->data;
	} else {
		// If there's free space, the total size is CHUNK_MIN_SIZE
		char *start = pool->chunks->data + CHUNK_MIN_SIZE - pool->n_free;
		pool->n_free -= len;
		out = start;
	}
	memcpy(out, data, len);
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
