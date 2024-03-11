#include <assert.h>
#include <sfdo-desktop-file.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "grow.h"
#include "hash.h"

#define RUNE_EOF (-1)
#define RUNE_NONE (-2)

#define N_LOCALES_MAX 4

struct sfdo_desktop_file_localized_entry {
	struct sfdo_hashmap_entry base;
	char *key;
	size_t key_len;
	char *value;
	size_t value_len;
	int line, column;
	uint8_t locale_match_level; // Locale index + 1
	bool has_default;
};

struct sfdo_desktop_file_seen_group {
	struct sfdo_desktop_file_seen_group *next;
	char name[];
};

struct sfdo_desktop_file_loader {
	sfdo_desktop_file_group_start_handler_t group_start_func;
	sfdo_desktop_file_group_entry_handler_t group_entry_func;
	sfdo_desktop_file_group_end_handler_t group_end_func;
	void *user_data;

	struct sfdo_desktop_file_seen_group *curr_group;
	size_t curr_group_name_len;
	int curr_group_line, curr_group_column;

	struct sfdo_hashmap group_set; // sfdo_hashmap_entry
	struct sfdo_hashmap entries; // sfdo_desktop_file_localized_entry

	int32_t rune;
	char rune_bytes[4];
	size_t rune_len;

	char *locales[N_LOCALES_MAX];
	size_t n_locales;

	char *buf;
	size_t buf_len, buf_cap;

	int line, column;
	FILE *fp;
	struct sfdo_desktop_file_error *error;
};

static bool noop_group_entry_handler(
		const struct sfdo_desktop_file_group_entry *group_entry, void *data) {
	(void)group_entry;
	(void)data;
	return true;
}

static bool noop_group_end_handler(const struct sfdo_desktop_file_group *group, void *data) {
	(void)group;
	(void)data;
	return true;
}

static bool noop_group_start_handler(const struct sfdo_desktop_file_group *group, void *data,
		sfdo_desktop_file_group_entry_handler_t *out_entry_handler,
		sfdo_desktop_file_group_end_handler_t *out_end_handler) {
	(void)group;
	(void)data;
	*out_entry_handler = noop_group_entry_handler;
	*out_end_handler = noop_group_end_handler;
	return true;
}

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
	}

	loader->rune = rune;
	return true;

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
	if (loader->buf_len == loader->buf_cap && !sfdo_grow(&loader->buf, &loader->buf_cap, 1)) {
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

	size_t name_len;
	if (!terminate_string(loader, &name_len)) {
		return false;
	}

	struct sfdo_hashmap_entry *map_entry =
			sfdo_hashmap_get(&loader->group_set, loader->buf, name_len);
	if (map_entry == NULL) {
		set_error_at(loader, SFDO_DESKTOP_FILE_ERROR_OOM, line, column);
		return false;
	} else if (map_entry->key != NULL) {
		set_error_at(loader, SFDO_DESKTOP_FILE_ERROR_DUPLICATE_GROUP, line, column);
		return false;
	}

	struct sfdo_desktop_file_seen_group *seen_group = malloc(sizeof(*seen_group) + loader->buf_len);
	if (seen_group == NULL) {
		set_error_at(loader, SFDO_DESKTOP_FILE_ERROR_OOM, line, column);
		return false;
	}
	memcpy(seen_group->name, loader->buf, loader->buf_len);

	seen_group->next = loader->curr_group;
	loader->curr_group = seen_group;

	loader->curr_group_name_len = name_len;
	loader->curr_group_line = line;
	loader->curr_group_column = line;

	map_entry->key = seen_group->name;

	struct sfdo_desktop_file_group group = {
		.name = map_entry->key,
		.name_len = name_len,
		.line = line,
		.column = column,
	};

	loader->group_entry_func = NULL;
	loader->group_end_func = NULL;

	if (!loader->group_start_func(
				&group, loader->user_data, &loader->group_entry_func, &loader->group_end_func)) {
		set_error_at(loader, SFDO_DESKTOP_FILE_ERROR_USER, line, column);
		return false;
	}

	if (loader->group_entry_func == NULL) {
		loader->group_entry_func = noop_group_entry_handler;
	}
	if (loader->group_end_func == NULL) {
		loader->group_end_func = noop_group_end_handler;
	}

	sfdo_hashmap_clear(&loader->entries);

	return true;
}

static bool read_entry(struct sfdo_desktop_file_loader *loader) {
	if (loader->curr_group == NULL) {
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

	size_t key_len;
	if (!terminate_string(loader, &key_len)) {
		return false;
	}

	struct sfdo_desktop_file_localized_entry *l_entry =
			sfdo_hashmap_get(&loader->entries, loader->buf, key_len);
	if (l_entry == NULL) {
		set_error_at(loader, SFDO_DESKTOP_FILE_ERROR_OOM, line, column);
		return false;
	} else if (l_entry->base.key == NULL) {
		l_entry->key = strdup(loader->buf);
		if (l_entry->key == NULL) {
			set_error_at(loader, SFDO_DESKTOP_FILE_ERROR_OOM, line, column);
			return false;
		}
		l_entry->key_len = key_len;
		l_entry->base.key = l_entry->key;

		l_entry->line = line;
		l_entry->column = column;
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

		for (uint8_t i = l_entry->locale_match_level; i < loader->n_locales; i++) {
			if (strcmp(loader->locales[i], loader->buf) == 0) {
				l_entry->locale_match_level = i + 1;
				overwrite_value = true;
				break;
			}
		}

	} else {
		if (l_entry->has_default) {
			set_error_at(loader, SFDO_DESKTOP_FILE_ERROR_DUPLICATE_KEY, line, column);
			return false;
		}
		l_entry->has_default = true;
		overwrite_value = true;
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
		free(l_entry->value);
		l_entry->value = NULL;
		l_entry->value_len = 0;
		reset_buf(loader);

		l_entry->line = line;
		l_entry->column = column;
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
		size_t value_len;
		if (!terminate_string(loader, &value_len)) {
			return false;
		}

		// Use malloc() in case the value has NUL characters (highly unlikely but still)
		l_entry->value = malloc(value_len + 1);
		if (l_entry->value == NULL) {
			set_error_at(loader, SFDO_DESKTOP_FILE_ERROR_OOM, line, column);
			return false;
		}
		memcpy(l_entry->value, loader->buf, loader->buf_len);
		l_entry->value_len = value_len;
	}

	return true;
}

static void clear_localized_entry(struct sfdo_desktop_file_localized_entry *l_entry) {
	free(l_entry->key);
	free(l_entry->value);
	*l_entry = (struct sfdo_desktop_file_localized_entry){0};
}

static bool end_group(struct sfdo_desktop_file_loader *loader) {
	if (loader->curr_group == NULL) {
		return true;
	}

	struct sfdo_hashmap *entries = &loader->entries;
	for (size_t i = 0; i < entries->cap; i++) {
		struct sfdo_desktop_file_localized_entry *l_entry =
				&((struct sfdo_desktop_file_localized_entry *)entries->mem)[i];
		if (l_entry->base.key != NULL) {
			if (!l_entry->has_default) {
				set_error_at(loader, SFDO_DESKTOP_FILE_ERROR_NO_DEFAULT_VALUE, l_entry->line,
						l_entry->column);
				return false;
			}
			struct sfdo_desktop_file_group_entry group_entry = {
				.key = l_entry->key,
				.key_len = l_entry->key_len,
				.value = l_entry->value,
				.value_len = l_entry->value_len,
				.line = l_entry->line,
				.column = l_entry->column,
			};
			if (!loader->group_entry_func(&group_entry, loader->user_data)) {
				set_error_at(loader, SFDO_DESKTOP_FILE_ERROR_USER, l_entry->line, l_entry->column);
				return false;
			}

			clear_localized_entry(l_entry);
		}
	}

	sfdo_hashmap_clear(entries);

	struct sfdo_desktop_file_group group = {
		.name = loader->curr_group->name,
		.name_len = loader->curr_group_name_len,
		.line = loader->curr_group_line,
		.column = loader->curr_group_column,
	};

	if (!loader->group_end_func(&group, loader->user_data)) {
		set_error(loader, SFDO_DESKTOP_FILE_ERROR_USER);
		return false;
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
			if (!end_group(loader)) {
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
			if (!end_group(loader)) {
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

	// lang + null terminator
	size_t locale_len = lang_len + 1;
	char *locale_p = malloc(locale_len);
	if (locale_p == NULL) {
		return false;
	}
	loader->locales[loader->n_locales++] = locale_p;
	memcpy(locale_p, str, lang_len);
	locale_p += lang_len;
	*locale_p = '\0';

	if (has_modifier) {
		// lang@MODIFIER + null terminator
		locale_len = lang_len + 1 + modifier_len + 1;
		locale_p = malloc(locale_len);
		if (locale_p == NULL) {
			return false;
		}
		loader->locales[loader->n_locales++] = locale_p;
		memcpy(locale_p, str, lang_len);
		locale_p += lang_len;
		*(locale_p++) = '@';
		memcpy(locale_p, str + modifier_i, modifier_len);
		locale_p += modifier_len;
		*locale_p = '\0';
	}

	if (has_country) {
		// lang_COUNTRY + null terminator
		locale_len = lang_len + 1 + country_len + 1;
		locale_p = malloc(locale_len);
		if (locale_p == NULL) {
			return false;
		}
		loader->locales[loader->n_locales++] = locale_p;
		memcpy(locale_p, str, lang_len);
		locale_p += lang_len;
		*(locale_p++) = '_';
		memcpy(locale_p, str + country_i, country_len);
		locale_p += country_len;
		*locale_p = '\0';
	}

	if (has_country && has_modifier) {
		// lang_COUNTRY@MODIFIER + null terminator
		locale_len = lang_len + 1 + country_len + 1 + modifier_len + 1;
		locale_p = malloc(locale_len);
		if (locale_p == NULL) {
			return false;
		}
		loader->locales[loader->n_locales++] = locale_p;
		memcpy(locale_p, str, lang_len);
		locale_p += lang_len;
		*(locale_p++) = '_';
		memcpy(locale_p, str + country_i, country_len);
		locale_p += country_len;
		*(locale_p++) = '@';
		memcpy(locale_p, str + modifier_i, modifier_len);
		locale_p += modifier_len;
		*locale_p = '\0';
	}

	return true;
}

SFDO_API bool sfdo_desktop_file_load(FILE *fp, struct sfdo_desktop_file_error *error,
		const char *locale, sfdo_desktop_file_group_start_handler_t group_start_handler,
		void *data) {
	struct sfdo_desktop_file_error placeholder;
	if (error == NULL) {
		error = &placeholder;
	}
	if (group_start_handler == NULL) {
		group_start_handler = noop_group_start_handler;
	}

	struct sfdo_desktop_file_loader loader = {
		.group_start_func = group_start_handler,
		.group_entry_func = noop_group_entry_handler,
		.group_end_func = noop_group_end_handler,
		.user_data = data,
		.rune = RUNE_NONE,
		.line = 1,
		.column = 1,
		.fp = fp,
		.error = error,
	};

	sfdo_hashmap_init(&loader.group_set, sizeof(struct sfdo_hashmap_entry));
	sfdo_hashmap_init(&loader.entries, sizeof(struct sfdo_desktop_file_localized_entry));

	bool ok = false;

	if (!prepare_locales(&loader, locale)) {
		set_error(&loader, SFDO_DESKTOP_FILE_ERROR_OOM);
	} else {
		ok = load(&loader);
	}

	for (size_t i = 0; i < loader.n_locales; i++) {
		free(loader.locales[i]);
	}

	free(loader.buf);

	struct sfdo_desktop_file_seen_group *seen_group = loader.curr_group;
	while (seen_group != NULL) {
		struct sfdo_desktop_file_seen_group *next = seen_group->next;
		free(seen_group);
		seen_group = next;
	}

	sfdo_hashmap_finish(&loader.group_set);

	struct sfdo_hashmap *entries = &loader.entries;
	for (size_t i = 0; i < entries->cap; i++) {
		struct sfdo_desktop_file_localized_entry *l_entry =
				&((struct sfdo_desktop_file_localized_entry *)entries->mem)[i];
		if (l_entry->base.key != NULL) {
			clear_localized_entry(l_entry);
		}
	}

	sfdo_hashmap_finish(entries);

	return ok;
}

SFDO_API const char *sfdo_desktop_file_error_code_get_description(
		enum sfdo_desktop_file_error_code code) {
	switch (code) {
	case SFDO_DESKTOP_FILE_ERROR_NONE:
		return "Success";
	case SFDO_DESKTOP_FILE_ERROR_IO:
		return "Input error";
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
	case SFDO_DESKTOP_FILE_ERROR_USER:
		return "User error";
	}
	abort(); // Unreachable
}
