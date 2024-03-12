#ifndef STRITER_H
#define STRITER_H

#include <stdbool.h>
#include <stddef.h>

bool sfdo_striter(const char *list, char sep, size_t *iter, size_t *start, size_t *len);

#endif
