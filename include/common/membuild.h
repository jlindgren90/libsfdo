#ifndef MEMBUILD_H
#define MEMBUILD_H

#include <stdbool.h>
#include <stddef.h>

struct sfdo_membuild {
	char *data;
	size_t len;
};

bool sfdo_membuild_setup(struct sfdo_membuild *membuild, size_t cap);

// (const char *, size_t)*, NULL
void sfdo_membuild_add(struct sfdo_membuild *membuild, ...);

#endif
