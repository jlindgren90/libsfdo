#include "striter.h"

bool sfdo_striter(const char *list, char sep, size_t *iter, size_t *start, size_t *len) {
	if (list[*iter] == '\0') {
		return false;
	}

	*start = *iter;
	while (true) {
		if (list[*iter] == '\0') {
			*len = *iter - *start;
			break;
		} else if (list[*iter] == sep) {
			*len = *iter - *start;
			++(*iter);
			break;
		} else {
			++(*iter);
		}
	}

	return true;
}
