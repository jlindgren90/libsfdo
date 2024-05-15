#include <errno.h>
#include <getopt.h>
#include <sfdo-desktop-file.h>
#include <stdlib.h>
#include <string.h>

struct query {
	const char *group_name;
	const char *key;
	size_t key_len;
};

static void die_usage(const char *prog) {
	printf("Usage: %s [-d] [-l locale] <path> [group:key...]\n", prog);
	exit(1);
}

int main(int argc, char **argv) {
	int options = SFDO_DESKTOP_FILE_LOAD_OPTIONS_DEFAULT;
	const char *locale = NULL;

	char *prog = argv[0];
	int opt;
	while ((opt = getopt(argc, argv, "dl:")) != -1) {
		switch (opt) {
		case 'd':
			options |= SFDO_DESKTOP_FILE_LOAD_ALLOW_DUPLICATE_GROUPS;
			break;
		case 'l':
			locale = optarg;
			break;
		default:
			die_usage(prog);
		}
	}

	argv += optind;
	argc -= optind;

	if (argc < 1) {
		die_usage(prog);
	}

	const char *path = argv[0];
	FILE *fp = fopen(path, "r");
	if (fp == NULL) {
		fprintf(stderr, "Failed to open: %s: %s\n", path, strerror(errno));
		return 1;
	}

	argv += 1;
	argc -= 1;

	struct query *queries = NULL;
	size_t n_queries = (size_t)argc;

	if (n_queries > 0) {
		queries = calloc(n_queries, sizeof(*queries));
		if (queries == NULL) {
			fprintf(stderr, "Memory allocation error\n");
			return 1;
		}
	}

	for (size_t i = 0; i < n_queries; i++) {
		char *query_s = argv[i];
		char *key_p = strchr(query_s, '/');
		if (key_p == NULL) {
			die_usage(prog);
		}
		*(key_p++) = '\0';
		struct query *query = &queries[i];
		query->group_name = query_s;
		query->key = key_p;
		query->key_len = strlen(query->key);
	}

	struct sfdo_desktop_file_error error;
	struct sfdo_desktop_file_document *doc =
			sfdo_desktop_file_document_load(fp, locale, options, &error);
	fclose(fp);

	if (doc == NULL) {
		fprintf(stderr, "%d:%d: %s\n", error.line, error.column,
				sfdo_desktop_file_error_code_get_description(error.code));
		return 1;
	}

	for (struct sfdo_desktop_file_group *group = sfdo_desktop_file_document_get_groups(doc);
			group != NULL; group = sfdo_desktop_file_group_get_next(group)) {
		const char *name = sfdo_desktop_file_group_get_name(group, NULL);

		for (size_t i = 0; i < n_queries; i++) {
			struct query *query = &queries[i];
			if (strcmp(query->group_name, name) == 0) {
				struct sfdo_desktop_file_entry *entry =
						sfdo_desktop_file_group_get_entry(group, query->key, query->key_len);
				if (entry != NULL) {
					const char *value = sfdo_desktop_file_entry_get_value(entry, NULL);
					printf("%s/%s: %s\n", name, query->key, value);
					break;
				}
			}
		}
	}

	sfdo_desktop_file_document_destroy(doc);
	free(queries);

	return 0;
}
