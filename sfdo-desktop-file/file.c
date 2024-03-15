#include <assert.h>
#include <sfdo-desktop-file.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "grow.h"
#include "hash.h"
#include "membuild.h"
#include "sfdo-common.h"

#define RUNE_EOF (-1)
#define RUNE_NONE (-2)

#define N_LOCALES_MAX 4

struct sfdo_desktop_file_entry {
	char *key;
	size_t key_len;
	char *value;
	size_t value_len;
	int line, column;
	uint8_t locale_match_level; // Locale index + 1
	bool has_default;
};

struct sfdo_desktop_file_map_entry {
	struct sfdo_hashmap_entry base;
	struct sfdo_desktop_file_entry *entry;
};

struct sfdo_desktop_file_group {
	struct sfdo_desktop_file_group *next;
	char *name;
	size_t name_len;
	int line, column;
	struct sfdo_hashmap entries; // sfdo_desktop_file_entry
};

struct sfdo_desktop_file_document {
	struct sfdo_desktop_file_group *groups;
};

struct sfdo_desktop_file_loader {
	struct sfdo_desktop_file_document *doc;
	struct sfdo_desktop_file_group *curr_group;

	struct sfdo_hashmap group_set; // sfdo_hashmap_entry

	int32_t rune;
	char rune_bytes[4];
	size_t rune_len;

	char *locale_data;
	const char *locales[N_LOCALES_MAX];
	size_t n_locales;

	char *buf;
	size_t buf_len, buf_cap;

	int line, column;
	FILE *fp;
	struct sfdo_desktop_file_error *error;

	bool allow_duplicate_groups;
};

static inline bool is_ws(int32_t rune) {
	return rune == ' ' || rune == '\t';
}

static inline bool is_end(int32_t rune) {
	return rune == '\n' || rune == RUNE_EOF;
}

static inline bool is_group_char(int32_t rune) {
	return rune >= 0x20 && rune <= 0x7e && rune != '[';
}

static inline bool is_key_char(int32_t rune) {
	return (rune >= 'A' && rune <= 'Z') || (rune >= 'a' && rune <= 'z') ||
			(rune >= '0' && rune <= '9') || rune == '-';
}

static void set_error_at(struct sfdo_desktop_file_loader *loader,
		enum sfdo_desktop_file_error_code code, int line, int column) {
	struct sfdo_desktop_file_error *error = loader->error;
	error->code = code;
	error->line = line;
	error->column = column;
}

static void set_error(
		struct sfdo_desktop_file_loader *loader, enum sfdo_desktop_file_error_code code) {
	set_error_at(loader, code, loader->line, loader->column);
}

static bool peek(struct sfdo_desktop_file_loader *loader) {
	if (loader->rune != RUNE_NONE) {
		return true;
	}

	int c = fgetc(loader->fp);
	if (c == EOF) {
		if (ferror(loader->fp)) {
			set_error(loader, SFDO_DESKTOP_FILE_ERROR_IO);
			return false;
		}
		loader->rune_len = 0;
		loader->rune = RUNE_EOF;
		return true;
	}

	int32_t rune = 0;

	char leader = (char)c;
	loader->rune_bytes[0] = leader;
	if ((leader & 0x80) == 0x00) {
		rune = leader;
		loader->rune_len = 1;
	} else if ((leader & 0xe0) == 0xc0) {
		rune = leader & 0x3f;
		loader->rune_len = 2;
	} else if ((leader & 0xf0) == 0xe0) {
		rune = leader & 0x1f;
		loader->rune_len = 3;
	} else if ((leader & 0xf8) == 0xf0) {
		rune = leader & 0x0f;
		loader->rune_len = 4;
	} else {
		set_error(loader, SFDO_DESKTOP_FILE_ERROR_UTF8);
		return false;
	}

	for (size_t i = 1; i < loader->rune_len; i++) {
		c = fgetc(loader->fp);
		if (c == EOF) {
			if (ferror(loader->fp)) {
				set_error(loader, SFDO_DESKTOP_FILE_ERROR_IO);
			} else {
				set_error(loader, SFDO_DESKTOP_FILE_ERROR_UTF8);
			}
			return false;
		}
		char cont = (char)c;
		loader->rune_bytes[i] = cont;
		if ((cont & 0xc0) != 0x80) {
			set_error(loader, SFDO_DESKTOP_FILE_ERROR_UTF8);
			return false;
		}
		rune = (rune << 6) | (cont & 0x3f);
	}

	size_t exp_len = rune <= 0x7f ? 1 : rune <= 0x7ff ? 2 : rune <= 0xffff ? 3 : 4;

	if (rune < 0 || rune > 0x10ffff || (rune >= 0xd8000 && rune <= 0xdffff) ||
			loader->rune_len != exp_len) {
		set_error(loader, SFDO_DESKTOP_FILE_ERROR_UTF8);
		return false;
	} else if (rune == 0) {
		set_error(loader, SFDO_DESKTOP_FILE_ERROR_NT);
		return false;
	}

	loader->rune = rune;
	return true;
}

static inline void advance(struct sfdo_desktop_file_loader *loader) {
	assert(loader->rune != RUNE_NONE);
	if (loader->rune == '\n') {
		++loader->line;
		loader->column = 1;
	} else {
		++loader->column;
	}
	loader->rune = RUNE_NONE;
}

static bool add_bytes(struct sfdo_desktop_file_loader *loader, char *bytes, size_t len) {
	if (loader->buf_len + len > loader->buf_cap && !sfdo_grow(&loader->buf, &loader->buf_cap, 1)) {
		set_error(loader, SFDO_DESKTOP_FILE_ERROR_OOM);
		return false;
	}
	memcpy(loader->buf + loader->buf_len, bytes, len);
	loader->buf_len += len;
	return true;
}

static inline bool add_rune(struct sfdo_desktop_file_loader *loader) {
	return add_bytes(loader, loader->rune_bytes, loader->rune_len);
}

static inline bool terminate_string(struct sfdo_desktop_file_loader *loader, size_t *len) {
	*len = loader->buf_len;
	return add_bytes(loader, "", 1);
}

static inline void reset_buf(struct sfdo_desktop_file_loader *loader) {
	loader->buf_len = 0;
}

static bool skip_ws(struct sfdo_desktop_file_loader *loader) {
	while (true) {
		if (!peek(loader)) {
			return false;
		} else if (!is_ws(loader->rune)) {
			break;
		}
		advance(loader);
	}
	return true;
}

static bool skip_ws_end(struct sfdo_desktop_file_loader *loader) {
	if (!skip_ws(loader)) {
		return false;
	}
	if (!is_end(loader->rune)) {
		set_error(loader, SFDO_DESKTOP_FILE_ERROR_SYNTAX);
		return false;
	}
	advance(loader);
	return true;
}

static bool skip_comment(struct sfdo_desktop_file_loader *loader) {
	assert(loader->rune == '#');
	while (true) {
		if (!peek(loader)) {
			return false;
		}
		if (is_end(loader->rune)) {
			break;
		}
		advance(loader);
	}
	advance(loader);
	return true;
}

static bool read_group(struct sfdo_desktop_file_loader *loader) {
	assert(loader->rune == '[');

	int line = loader->line;
	int column = loader->column;

	advance(loader);

	reset_buf(loader);

	while (true) {
		if (!peek(loader)) {
			return false;
		}
		if (loader->rune == ']') {
			break;
		} else if (!is_group_char(loader->rune)) {
			set_error(loader, SFDO_DESKTOP_FILE_ERROR_SYNTAX);
			return false;
		}
		if (!add_rune(loader)) {
			return false;
		}
		advance(loader);
	}

	assert(loader->rune == ']');
	advance(loader);

	if (!skip_ws_end(loader)) {
		return false;
	}

	struct sfdo_hashmap_entry *map_entry =
			sfdo_hashmap_get(&loader->group_set, loader->buf, loader->buf_len, true);
	if (map_entry == NULL) {
		set_error_at(loader, SFDO_DESKTOP_FILE_ERROR_OOM, line, column);
		return false;
	} else if (map_entry->key != NULL && !loader->allow_duplicate_groups) {
		set_error_at(loader, SFDO_DESKTOP_FILE_ERROR_DUPLICATE_GROUP, line, column);
		return false;
	}

	char *name = malloc(loader->buf_len + 1);
	if (name == NULL) {
		set_error_at(loader, SFDO_DESKTOP_FILE_ERROR_OOM, line, column);
		return false;
	}
	memcpy(name, loader->buf, loader->buf_len);
	name[loader->buf_len] = '\0';

	struct sfdo_desktop_file_group *group = calloc(1, sizeof(*group));
	if (group == NULL) {
		set_error_at(loader, SFDO_DESKTOP_FILE_ERROR_OOM, line, column);
		free(name);
		return false;
	}
	group->name = name;
	group->name_len = loader->buf_len;
	group->line = line;
	group->column = column;

	map_entry->key = name;

	sfdo_hashmap_init(&group->entries, sizeof(struct sfdo_desktop_file_map_entry));

	if (loader->curr_group == NULL) {
		loader->doc->groups = group;
	} else {
		loader->curr_group->next = group;
	}
	loader->curr_group = group;

	return true;
}

static bool read_entry(struct sfdo_desktop_file_loader *loader) {
	struct sfdo_desktop_file_group *group = loader->curr_group;
	if (group == NULL) {
		// An entry without a group
		set_error(loader, SFDO_DESKTOP_FILE_ERROR_SYNTAX);
		return false;
	}

	int line = loader->line;
	int column = loader->column;

	reset_buf(loader);

	while (true) {
		if (!peek(loader)) {
			return false;
		}
		int32_t rune = loader->rune;
		if (is_ws(rune) || rune == '=' || rune == '[') {
			break;
		} else if (!is_key_char(rune)) {
			set_error(loader, SFDO_DESKTOP_FILE_ERROR_SYNTAX);
			return false;
		}
		if (!add_rune(loader)) {
			return false;
		}
		advance(loader);
	}

	struct sfdo_desktop_file_map_entry *map_entry =
			sfdo_hashmap_get(&group->entries, loader->buf, loader->buf_len, true);
	struct sfdo_desktop_file_entry *entry = NULL;
	if (map_entry == NULL) {
		set_error_at(loader, SFDO_DESKTOP_FILE_ERROR_OOM, line, column);
		return false;
	} else if (map_entry->base.key == NULL) {
		entry = calloc(1, sizeof(*entry));
		if (entry == NULL) {
			set_error_at(loader, SFDO_DESKTOP_FILE_ERROR_OOM, line, column);
			return false;
		}

		entry->key = malloc(loader->buf_len + 1);
		if (entry->key == NULL) {
			set_error_at(loader, SFDO_DESKTOP_FILE_ERROR_OOM, line, column);
			free(entry);
			return false;
		}
		memcpy(entry->key, loader->buf, loader->buf_len);
		entry->key[loader->buf_len] = '\0';
		entry->key_len = loader->buf_len;

		entry->line = line;
		entry->column = column;

		map_entry->base.key = entry->key;
		map_entry->entry = entry;
	} else {
		entry = map_entry->entry;
	}

	bool overwrite_value = false;

	if (loader->rune == '[') {
		reset_buf(loader);
		advance(loader);

		while (true) {
			if (!peek(loader)) {
				return false;
			}
			if (is_end(loader->rune)) {
				set_error(loader, SFDO_DESKTOP_FILE_ERROR_SYNTAX);
				return false;
			} else if (loader->rune == ']') {
				break;
			}
			if (!add_rune(loader)) {
				return false;
			}
			advance(loader);
		}

		assert(loader->rune == ']');
		advance(loader);

		size_t locale_len;
		if (!terminate_string(loader, &locale_len)) {
			return false;
		}

		for (uint8_t i = entry->locale_match_level; i < loader->n_locales; i++) {
			if (strcmp(loader->locales[i], loader->buf) == 0) {
				entry->locale_match_level = i + 1;
				overwrite_value = true;
				break;
			}
		}
	} else {
		if (entry->has_default) {
			set_error_at(loader, SFDO_DESKTOP_FILE_ERROR_DUPLICATE_KEY, line, column);
			return false;
		}
		entry->has_default = true;
		if (entry->locale_match_level == 0) {
			overwrite_value = true;
		}
	}

	if (!skip_ws(loader)) {
		return false;
	}
	if (loader->rune != '=') {
		set_error(loader, SFDO_DESKTOP_FILE_ERROR_SYNTAX);
		return false;
	}
	advance(loader);
	if (!skip_ws(loader)) {
		return false;
	}

	if (overwrite_value) {
		free(entry->value);
		entry->value = NULL;
		entry->value_len = 0;
		reset_buf(loader);

		entry->line = line;
		entry->column = column;
	}

	line = loader->line;
	column = loader->column;

	bool escaped = false;
	while (true) {
		if (!peek(loader)) {
			return false;
		}
		int32_t rune = loader->rune;
		if (is_end(rune)) {
			break;
		} else if (escaped) {
			switch (rune) {
			case 's':
				rune = ' ';
				break;
			case 'n':
				rune = '\n';
				break;
			case 't':
				rune = '\t';
				break;
			case 'r':
				rune = '\r';
				break;
			case '\\':
				rune = '\\';
				break;
			default:
				set_error(loader, SFDO_DESKTOP_FILE_ERROR_SYNTAX);
				return false;
			}
			escaped = false;
		} else if (rune == '\\') {
			escaped = true;
			continue;
		}
		if (overwrite_value && !add_rune(loader)) {
			return false;
		}
		advance(loader);
	}
	if (escaped) {
		set_error(loader, SFDO_DESKTOP_FILE_ERROR_SYNTAX);
		return false;
	}

	if (!skip_ws_end(loader)) {
		return false;
	}

	if (overwrite_value) {
		entry->value = malloc(loader->buf_len + 1);
		if (entry->value == NULL) {
			set_error_at(loader, SFDO_DESKTOP_FILE_ERROR_OOM, line, column);
			return false;
		}
		memcpy(entry->value, loader->buf, loader->buf_len);
		entry->value[loader->buf_len] = '\0';
		entry->value_len = loader->buf_len;
	}

	return true;
}

static bool validate_group(struct sfdo_desktop_file_loader *loader) {
	struct sfdo_desktop_file_group *group = loader->curr_group;
	if (group == NULL) {
		return true;
	}

	struct sfdo_hashmap *entries = &group->entries;
	for (size_t i = 0; i < entries->cap; i++) {
		struct sfdo_desktop_file_map_entry *map_entry =
				&((struct sfdo_desktop_file_map_entry *)entries->mem)[i];
		if (map_entry->base.key != NULL) {
			struct sfdo_desktop_file_entry *entry = map_entry->entry;
			assert(entry != NULL);
			if (!entry->has_default) {
				set_error_at(loader, SFDO_DESKTOP_FILE_ERROR_NO_DEFAULT_VALUE, entry->line,
						entry->column);
				return false;
			}
		}
	}

	return true;
}

static bool load(struct sfdo_desktop_file_loader *loader) {
	while (true) {
		if (!skip_ws(loader)) {
			return false;
		}

		switch (loader->rune) {
		case RUNE_EOF:
			if (!validate_group(loader)) {
				return false;
			}
			return true;
		case '\n':
			advance(loader);
			continue;
		case '#':
			if (!skip_comment(loader)) {
				return false;
			}
			break;
		case '[':
			if (!validate_group(loader)) {
				return false;
			}
			if (!read_group(loader)) {
				return false;
			}
			break;
		default:
			if (!read_entry(loader)) {
				return false;
			}
			break;
		}
	}
}

static bool prepare_locales(struct sfdo_desktop_file_loader *loader, const char *str) {
	loader->n_locales = 0;

	if (str == NULL) {
		return true;
	}

	size_t lang_len = strcspn(str, "_.@");
	if (lang_len == 0) {
		return true;
	}

	size_t country_i = 0;
	size_t country_len = 0;
	size_t modifier_i = 0;
	size_t modifier_len = 0;

	size_t len = lang_len;

	if (str[len] == '_') {
		country_i = ++len;
		country_len = strcspn(str + len, ".@");
		len += country_len;
	}
	if (str[len] == '.') {
		++len;
		len += strcspn(str + len, "@");
	}
	if (str[len] == '@') {
		modifier_i = ++len;
		modifier_len = strlen(str + len);
		len += modifier_len;
	}

	bool has_country = country_len > 0;
	bool has_modifier = modifier_len > 0;

	size_t mem_size = lang_len + 1;
	if (has_modifier) {
		mem_size += lang_len + 1 + modifier_len + 1;
	}
	if (has_country) {
		mem_size += lang_len + 1 + country_len + 1;
	}
	if (has_country && has_modifier) {
		mem_size += lang_len + 1 + country_len + 1 + modifier_len + 1;
	}

	struct sfdo_membuild mem_buf;
	if (!sfdo_membuild_setup(&mem_buf, mem_size)) {
		return false;
	}

	loader->locales[loader->n_locales++] = mem_buf.data + mem_buf.len;
	sfdo_membuild_add(&mem_buf, str, lang_len, "", 1, NULL);
	if (has_modifier) {
		loader->locales[loader->n_locales++] = mem_buf.data + mem_buf.len;
		sfdo_membuild_add(
				&mem_buf, str, lang_len, "@", 1, str + modifier_i, modifier_len, "", 1, NULL);
	}
	if (has_country) {
		loader->locales[loader->n_locales++] = mem_buf.data + mem_buf.len;
		sfdo_membuild_add(
				&mem_buf, str, lang_len, "_", 1, str + country_i, country_len, "", 1, NULL);
	}
	if (has_country && has_modifier) {
		loader->locales[loader->n_locales++] = mem_buf.data + mem_buf.len;
		sfdo_membuild_add(&mem_buf, str, lang_len, "_", 1, str + country_i, country_len, "@", 1,
				str + modifier_i, modifier_len, "", 1, NULL);
	}

	loader->locale_data = mem_buf.data;
	assert(mem_buf.len == mem_size);

	return true;
}

SFDO_API struct sfdo_desktop_file_document *sfdo_desktop_file_document_load(
		FILE *fp, const char *locale, int options, struct sfdo_desktop_file_error *error) {
	struct sfdo_desktop_file_error placeholder;
	if (error == NULL) {
		error = &placeholder;
	}

	struct sfdo_desktop_file_loader loader = {
		.rune = RUNE_NONE,
		.line = 1,
		.column = 1,
		.fp = fp,
		.error = error,
		.allow_duplicate_groups = (options & SFDO_DESKTOP_FILE_LOAD_ALLOW_DUPLICATE_GROUPS) != 0,
	};

	loader.doc = calloc(1, sizeof(*loader.doc));
	if (loader.doc == NULL) {
		set_error(&loader, SFDO_DESKTOP_FILE_ERROR_OOM);
		return NULL;
	}

	if (!prepare_locales(&loader, locale)) {
		set_error(&loader, SFDO_DESKTOP_FILE_ERROR_OOM);
		free(loader.doc);
		return NULL;
	}

	sfdo_hashmap_init(&loader.group_set, sizeof(struct sfdo_hashmap_entry));

	bool ok = load(&loader);

	sfdo_hashmap_finish(&loader.group_set);
	free(loader.locale_data);
	free(loader.buf);

	if (ok) {
		return loader.doc;
	} else {
		sfdo_desktop_file_document_destroy(loader.doc);
		return NULL;
	}
}

SFDO_API void sfdo_desktop_file_document_destroy(struct sfdo_desktop_file_document *document) {
	if (document == NULL) {
		return;
	}

	struct sfdo_desktop_file_group *group = document->groups;
	while (group != NULL) {
		struct sfdo_desktop_file_group *next = group->next;

		struct sfdo_hashmap *entries = &group->entries;
		for (size_t i = 0; i < entries->cap; i++) {
			struct sfdo_desktop_file_map_entry *map_entry =
					&((struct sfdo_desktop_file_map_entry *)entries->mem)[i];
			if (map_entry->base.key != NULL) {
				struct sfdo_desktop_file_entry *entry = map_entry->entry;
				assert(entry != NULL);
				free(entry->key);
				free(entry->value);
				free(entry);
			}
		}
		sfdo_hashmap_finish(entries);

		free(group->name);
		free(group);
		group = next;
	}

	free(document);
}

SFDO_API struct sfdo_desktop_file_group *sfdo_desktop_file_document_get_groups(
		struct sfdo_desktop_file_document *document) {
	return document->groups;
}

SFDO_API const char *sfdo_desktop_file_error_code_get_description(
		enum sfdo_desktop_file_error_code code) {
	switch (code) {
	case SFDO_DESKTOP_FILE_ERROR_NONE:
		return "Success";
	case SFDO_DESKTOP_FILE_ERROR_IO:
		return "Input error";
	case SFDO_DESKTOP_FILE_ERROR_NT:
		return "Unexpected NUL";
	case SFDO_DESKTOP_FILE_ERROR_UTF8:
		return "Invalid UTF-8 sequence";
	case SFDO_DESKTOP_FILE_ERROR_OOM:
		return "Out of memory";
	case SFDO_DESKTOP_FILE_ERROR_SYNTAX:
		return "Syntax error";
	case SFDO_DESKTOP_FILE_ERROR_DUPLICATE_GROUP:
		return "Duplicate group";
	case SFDO_DESKTOP_FILE_ERROR_DUPLICATE_KEY:
		return "Duplicate key";
	case SFDO_DESKTOP_FILE_ERROR_NO_DEFAULT_VALUE:
		return "No default value";
	}
	abort(); // Unreachable
}

SFDO_API struct sfdo_desktop_file_group *sfdo_desktop_file_group_get_next(
		struct sfdo_desktop_file_group *group) {
	return group->next;
}

SFDO_API const char *sfdo_desktop_file_group_get_name(
		struct sfdo_desktop_file_group *group, size_t *len) {
	if (len != NULL) {
		*len = group->name_len;
	}
	return group->name;
}

SFDO_API void sfdo_desktop_file_group_get_location(
		struct sfdo_desktop_file_group *group, int *line, int *column) {
	if (line != NULL) {
		*line = group->line;
	}
	if (column != NULL) {
		*column = group->column;
	}
}

SFDO_API struct sfdo_desktop_file_entry *sfdo_desktop_file_group_get_entry(
		struct sfdo_desktop_file_group *group, const char *key, size_t key_len) {
	if (key_len == SFDO_NT) {
		key_len = strlen(key);
	}
	struct sfdo_desktop_file_map_entry *map_entry =
			sfdo_hashmap_get(&group->entries, key, key_len, false);
	if (map_entry == NULL) {
		return NULL;
	}
	return map_entry->entry;
}

SFDO_API const char *sfdo_desktop_file_entry_get_key(
		struct sfdo_desktop_file_entry *entry, size_t *len) {
	if (len != NULL) {
		*len = entry->key_len;
	}
	return entry->key;
}

SFDO_API const char *sfdo_desktop_file_entry_get_value(
		struct sfdo_desktop_file_entry *entry, size_t *len) {
	if (len != NULL) {
		*len = entry->value_len;
	}
	return entry->value;
}

SFDO_API void sfdo_desktop_file_entry_get_location(
		struct sfdo_desktop_file_entry *entry, int *line, int *column) {
	if (line != NULL) {
		*line = entry->line;
	}
	if (column != NULL) {
		*column = entry->column;
	}
}
