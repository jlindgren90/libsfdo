#ifndef STRBUILD_H
#define STRBUILD_H

#include <stdbool.h>
#include <stddef.h>

struct sfdo_strbuild {
	char *data;
	size_t len, cap;
};

void sfdo_strbuild_init(struct sfdo_strbuild *strbuild);
void sfdo_strbuild_finish(struct sfdo_strbuild *strbuild);

void sfdo_strbuild_reset(struct sfdo_strbuild *strbuild);

// (const char *, size_t)*, NULL
bool sfdo_strbuild_add(struct sfdo_strbuild *strbuild, ...);

#endif
