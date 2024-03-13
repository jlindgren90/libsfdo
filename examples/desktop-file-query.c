#include <errno.h>
#include <getopt.h>
#include <sfdo-desktop-file.h>
#include <stdlib.h>
#include <string.h>

struct query {
	const char *group_name;
	const char *key;
};

struct ctx {
	struct query *queries;
	size_t n_queries;
};

static bool start_handler(struct sfdo_desktop_file_group *group, void *data) {
	struct ctx *ctx = data;

	const char *name = sfdo_desktop_file_group_get_name(group, NULL);

	for (size_t i = 0; i < ctx->n_queries; i++) {
		struct query *query = &ctx->queries[i];
		if (strcmp(query->group_name, name) == 0) {
			struct sfdo_desktop_file_entry *entry =
					sfdo_desktop_file_group_get_entry(group, query->key);
			if (entry != NULL) {
				const char *value = sfdo_desktop_file_entry_get_value(entry, NULL);
				printf("%s/%s: %s\n", name, query->key, value);
				break;
			}
		}
	}

	return true;
}

static void die_usage(const char *prog) {
	printf("Usage: %s [-D] [-l locale] <path> [group:key...]\n", prog);
	exit(1);
}

int main(int argc, char **argv) {
	int options = SFDO_DESKTOP_FILE_LOAD_OPTIONS_DEFAULT;
	const char *locale = NULL;

	char *prog = argv[0];
	int opt;
	while ((opt = getopt(argc, argv, "Dl:")) != -1) {
		switch (opt) {
		case 'D':
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

	struct ctx ctx = {
		.n_queries = (size_t)argc,
		.queries = NULL,
	};

	if (argc > 0) {
		ctx.queries = calloc(ctx.n_queries, sizeof(*ctx.queries));
		if (ctx.queries == NULL) {
			fprintf(stderr, "Memory allocation error\n");
			return 1;
		}
	}

	for (size_t i = 0; i < ctx.n_queries; i++) {
		char *query_s = argv[i];
		char *key_p = strchr(query_s, '/');
		if (key_p == NULL) {
			printf("hm?\n");
			die_usage(prog);
		}
		*(key_p++) = '\0';
		struct query *query = &ctx.queries[i];
		query->group_name = query_s;
		query->key = key_p;
	}

	struct sfdo_desktop_file_error error;
	bool ok = sfdo_desktop_file_load(fp, &error, locale, start_handler, &ctx, options);
	fclose(fp);

	free(ctx.queries);

	if (!ok) {
		fprintf(stderr, "%d:%d: %s\n", error.line, error.column,
				sfdo_desktop_file_error_code_get_description(error.code));
		return 1;
	}

	return 0;
}
