#ifndef STRPOOL_H
#define STRPOOL_H

#include <stdbool.h>
#include <stddef.h>

struct sfdo_strpool_chunk;

struct sfdo_strpool {
	struct sfdo_strpool_chunk *chunks;
	size_t n_free;
};

struct sfdo_strpool_state {
	struct sfdo_strpool_chunk *chunk;
	size_t n_free;
};

void sfdo_strpool_init(struct sfdo_strpool *pool);
void sfdo_strpool_finish(struct sfdo_strpool *pool);

// data must be null-terminated
char *sfdo_strpool_add(struct sfdo_strpool *pool, const char *data, size_t len);

void sfdo_strpool_save(struct sfdo_strpool *pool, struct sfdo_strpool_state *state);
void sfdo_strpool_restore(struct sfdo_strpool *pool, struct sfdo_strpool_state *state);

#endif
