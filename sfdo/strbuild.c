#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "strbuild.h"

static void add_args(struct sfdo_strbuild *strbuild, va_list args) {
	const char *data;
	while ((data = va_arg(args, const char *)) != NULL) {
		size_t len = va_arg(args, size_t);
		memcpy(&strbuild->data[strbuild->len], data, len);
		strbuild->len += len;
	}
}

void sfdo_strbuild_init(struct sfdo_strbuild *strbuild) {
	strbuild->data = NULL;
	strbuild->len = strbuild->cap = 0;
}

void sfdo_strbuild_finish(struct sfdo_strbuild *strbuild) {
	free(strbuild->data);
}

void sfdo_strbuild_reset(struct sfdo_strbuild *strbuild) {
	strbuild->len = 0;
}

bool sfdo_strbuild_add(struct sfdo_strbuild *strbuild, ...) {
	va_list args;
	va_start(args, strbuild);

	size_t total_len = 0;
	while (va_arg(args, const char *) != NULL) {
		total_len += va_arg(args, size_t);
	}

	va_end(args);

	size_t cap = strbuild->cap == 0 ? 4096 : strbuild->cap;
	// end must be strictly bigger than cap to have space for a null terminator
	size_t end = strbuild->len + total_len;
	while (end >= cap) {
		if (cap > SIZE_MAX / 2) {
			return false;
		}
		cap *= 2;
	}
	if (strbuild->cap != cap) {
		char *pb_data = realloc(strbuild->data, cap);
		if (pb_data == NULL) {
			return false;
		}
		strbuild->data = pb_data;
		strbuild->cap = cap;
	}

	va_start(args, strbuild);
	add_args(strbuild, args);
	va_end(args);

	strbuild->data[strbuild->len] = '\0';

	return true;
}

bool sfdo_strbuild_setup_capped(struct sfdo_strbuild *strbuild, size_t cap) {
	if (cap > 0) {
		strbuild->data = malloc(cap);
		if (strbuild->data == NULL) {
			return false;
		}
	} else {
		strbuild->data = NULL;
	}
	strbuild->len = 0;
	strbuild->cap = cap;
	return true;
}

void sfdo_strbuild_add_raw(struct sfdo_strbuild *strbuild, ...) {
	va_list args;
	va_start(args, strbuild);
	add_args(strbuild, args);
	va_end(args);
}
