#include <errno.h>
#include <sfdo-desktop-file.h>
#include <string.h>

static bool entry_handler(const struct sfdo_desktop_file_group_entry *entry, void *data) {
	(void)data;
	printf("  %s: %s\n", entry->key, entry->value);
	return true;
}

static bool end_handler(const struct sfdo_desktop_file_group *group, void *data) {
	(void)group;
	(void)data;
	return true;
}

static bool start_handler(const struct sfdo_desktop_file_group *group, void *data,
		sfdo_desktop_file_group_entry_handler_t *out_entry_handler,
		sfdo_desktop_file_group_end_handler_t *out_end_handler) {
	(void)data;
	printf("%s:\n", group->name);
	*out_entry_handler = entry_handler;
	*out_end_handler = end_handler;
	return true;
}

int main(int argc, char **argv) {
	if (argc < 2 || argc > 3) {
		fprintf(stderr, "Usage: %s <path> [locale]\n", argv[0]);
		return 1;
	}

	const char *path = argv[1];
	FILE *fp = fopen(path, "r");
	if (fp == NULL) {
		fprintf(stderr, "Failed to open: %s: %s\n", path, strerror(errno));
		return 1;
	}

	const char *locale = NULL;
	if (argc == 3) {
		locale = argv[2];
	}

	struct sfdo_desktop_file_error error;
	bool ok = sfdo_desktop_file_load(fp, &error, locale, start_handler, NULL);
	fclose(fp);

	if (!ok) {
		fprintf(stderr, "%d:%d: %s\n", error.line, error.column,
				sfdo_desktop_file_error_code_get_description(error.code));
		return 1;
	}

	return 0;
}
