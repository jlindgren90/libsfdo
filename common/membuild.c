#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "common/membuild.h"

bool sfdo_membuild_setup(struct sfdo_membuild *membuild, size_t cap) {
	if (cap > 0) {
		membuild->data = malloc(cap);
		if (membuild->data == NULL) {
			return false;
		}
	} else {
		membuild->data = NULL;
	}
	membuild->len = 0;
	return true;
}

void sfdo_membuild_add(struct sfdo_membuild *membuild, ...) {
	va_list args;
	va_start(args, membuild);

	const char *data;
	while ((data = va_arg(args, const char *)) != NULL) {
		size_t len = va_arg(args, size_t);
		memcpy(&membuild->data[membuild->len], data, len);
		membuild->len += len;
	}

	va_end(args);
}
