#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <sfdo-desktop-file.h>
#include <sfdo-desktop.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "common/api.h"
#include "common/dirs.h"
#include "common/grow.h"
#include "common/strbuild.h"
#include "common/striter.h"
#include "common/strpool.h"
#include "sfdo-desktop/internal.h"

#define ENTRY_DESKTOP_SUFFIX ".desktop"
#define ENTRY_DIRECTORY_SUFFIX ".directory"

#define DESKTOP_ACTION_PREFIX "Desktop Action "

struct sfdo_desktop_exec_scanner {
	struct sfdo_desktop_entry *entry;

	const char *data;
	size_t data_len;
	int line, column;

	struct sfdo_desktop_exec *dst;

	size_t i; // index in exec

	char *buf;
	size_t buf_len, buf_cap;

	const char **lit_buf;
	size_t lit_buf_len, lit_buf_cap;
};

struct sfdo_desktop_loader {
	struct sfdo_desktop_db *db;
	const char *locale;

	size_t n_entries;

	struct sfdo_strbuild path_buf;
	struct sfdo_strbuild id_buf;

	struct sfdo_desktop_exec_scanner exec;
};

enum sfdo_desktop_entry_load_result {
	SFDO_DESKTOP_ENTRY_LOAD_OK,
	SFDO_DESKTOP_ENTRY_LOAD_ERROR,
	SFDO_DESKTOP_ENTRY_LOAD_OOM,
};

enum sfdo_desktop_entry_value_req {
	SFDO_DESKTOP_ENTRY_VALUE_OPTIONAL,
	SFDO_DESKTOP_ENTRY_VALUE_REQUIRED,
};

enum sfdo_desktop_entry_value_type {
	SFDO_DESKTOP_ENTRY_VALUE_STRING,
	// Also used for iconstring
	SFDO_DESKTOP_ENTRY_VALUE_LOCALESTRING,
};

static void exec_finish(struct sfdo_desktop_exec *exec) {
	free(exec->literals);
}

static void desktop_entry_destroy(struct sfdo_desktop_entry *entry) {
	if (entry == NULL) {
		return;
	}

	free(entry->show_exceptions);
	free(entry->implements);

	switch (entry->type) {
	case SFDO_DESKTOP_ENTRY_APPLICATION:
		free(entry->app.mimetypes);
		free(entry->app.categories);
		free(entry->app.keywords);
		exec_finish(&entry->app.exec);
		for (size_t i = 0; i < entry->app.n_actions; i++) {
			struct sfdo_desktop_entry_action *action = entry->app.actions[i];
			exec_finish(&action->exec);
		}
		free(entry->app.actions);
		free(entry->app.actions_mem);
		break;
	case SFDO_DESKTOP_ENTRY_LINK:
		break;
	case SFDO_DESKTOP_ENTRY_DIRECTORY:
		break;
	}

	free(entry);
}

static enum sfdo_desktop_entry_load_result load_optional_boolean(struct sfdo_desktop_loader *loader,
		struct sfdo_desktop_file_group *group, const char *key, size_t key_len, bool *dst,
		bool *exists) {
	struct sfdo_desktop_db *db = loader->db;
	struct sfdo_logger *logger = &db->ctx->logger;

	struct sfdo_desktop_file_entry *entry;
	if ((entry = sfdo_desktop_file_group_get_entry(group, key, key_len)) != NULL) {
		size_t value_len;
		const char *value = sfdo_desktop_file_entry_get_value(entry, &value_len);
		if (value_len == 4 && memcmp(value, "true", 4) == 0) {
			*dst = true;
		} else if (value_len == 5 && memcmp(value, "false", 5) == 0) {
			*dst = false;
		} else {
			int line, column;
			sfdo_desktop_file_entry_get_location(entry, &line, &column);
			logger_write(logger, SFDO_LOG_LEVEL_ERROR, "%d:%d: expected true or false, got \"%s\"",
					line, column, value);
			return SFDO_DESKTOP_ENTRY_LOAD_ERROR;
		}
		*exists = true;
	} else {
		*dst = false;
		*exists = false;
	}
	return SFDO_DESKTOP_ENTRY_LOAD_OK;
}

static enum sfdo_desktop_entry_load_result load_boolean(struct sfdo_desktop_loader *loader,
		struct sfdo_desktop_file_group *group, const char *key, size_t key_len, bool *dst) {
	bool exists;
	return load_optional_boolean(loader, group, key, key_len, dst, &exists);
}

static enum sfdo_desktop_entry_load_result store_string(struct sfdo_desktop_loader *loader,
		const char *value, size_t value_len, struct sfdo_string *dst) {
	struct sfdo_desktop_db *db = loader->db;
	struct sfdo_logger *logger = &db->ctx->logger;

	const char *owned = sfdo_strpool_add(&db->strings, value, value_len);
	if (owned == NULL) {
		logger_write_oom(logger);
		return SFDO_DESKTOP_ENTRY_LOAD_OOM;
	}

	dst->data = owned;
	dst->len = value_len;
	return SFDO_DESKTOP_ENTRY_LOAD_OK;
}

static enum sfdo_desktop_entry_load_result load_string(struct sfdo_desktop_loader *loader,
		struct sfdo_desktop_file_group *group, const char *key, size_t key_len,
		enum sfdo_desktop_entry_value_req req, enum sfdo_desktop_entry_value_type type,
		struct sfdo_string *dst) {
	struct sfdo_desktop_db *db = loader->db;
	struct sfdo_logger *logger = &db->ctx->logger;

	struct sfdo_desktop_file_entry *entry;
	if ((entry = sfdo_desktop_file_group_get_entry(group, key, key_len)) != NULL) {
		size_t value_len;
		const char *value = NULL;
		switch (type) {
		case SFDO_DESKTOP_ENTRY_VALUE_STRING:
			value = sfdo_desktop_file_entry_get_value(entry, &value_len);
			break;
		case SFDO_DESKTOP_ENTRY_VALUE_LOCALESTRING:
			value = sfdo_desktop_file_entry_get_localized_value(entry, &value_len);
			break;
		}
		assert(value != NULL);
		return store_string(loader, value, value_len, dst);
	} else if (req == SFDO_DESKTOP_ENTRY_VALUE_REQUIRED) {
		int group_line, group_column;
		sfdo_desktop_file_group_get_location(group, &group_line, &group_column);
		logger_write(
				logger, SFDO_LOG_LEVEL_ERROR, "%d:%d: %s is unset", group_line, group_column, key);
		return SFDO_DESKTOP_ENTRY_LOAD_ERROR;
	}

	return SFDO_DESKTOP_ENTRY_LOAD_OK;
}

static enum sfdo_desktop_entry_load_result store_list(struct sfdo_desktop_loader *loader,
		const struct sfdo_string *src, size_t n_src, struct sfdo_string **dst, size_t *n_dst) {
	struct sfdo_desktop_db *db = loader->db;
	struct sfdo_logger *logger = &db->ctx->logger;

	*n_dst = n_src;
	if (n_src == 0) {
		*dst = NULL;
		return SFDO_DESKTOP_ENTRY_LOAD_OK;
	}

	struct sfdo_string *items = calloc(n_src, sizeof(*items));
	if (items == NULL) {
		logger_write_oom(logger);
		return SFDO_DESKTOP_ENTRY_LOAD_OOM;
	}

	for (size_t i = 0; i < n_src; i++) {
		const struct sfdo_string *src_item = &src[i];
		struct sfdo_string *item = &items[i];
		item->data = sfdo_strpool_add(&db->strings, src_item->data, src_item->len);
		if (item->data == NULL) {
			logger_write_oom(logger);
			free(items);
			return SFDO_DESKTOP_ENTRY_LOAD_OOM;
		}
		item->len = src_item->len;
	}

	*dst = items;
	return SFDO_DESKTOP_ENTRY_LOAD_OK;
}

static enum sfdo_desktop_entry_load_result load_list(struct sfdo_desktop_loader *loader,
		struct sfdo_desktop_file_group *group, const char *key, size_t key_len,
		enum sfdo_desktop_entry_value_type type, struct sfdo_string **dst, size_t *n_dst) {
	struct sfdo_desktop_file_entry *entry;
	if ((entry = sfdo_desktop_file_group_get_entry(group, key, key_len)) != NULL) {
		const struct sfdo_string *items = NULL;
		size_t n_items = 0;
		switch (type) {
		case SFDO_DESKTOP_ENTRY_VALUE_STRING:
			items = sfdo_desktop_file_entry_get_value_list(entry, &n_items);
			break;
		case SFDO_DESKTOP_ENTRY_VALUE_LOCALESTRING:
			items = sfdo_desktop_file_entry_get_localized_value_list(entry, &n_items);
			break;
		}
		return store_list(loader, items, n_items, dst, n_dst);
	} else {
		*dst = NULL;
		*n_dst = 0;
	}

	return SFDO_DESKTOP_ENTRY_LOAD_OK;
}

static enum sfdo_desktop_entry_load_result load_actions(struct sfdo_desktop_loader *loader,
		struct sfdo_desktop_file_group *group, struct sfdo_desktop_entry_action **dst_mem,
		struct sfdo_desktop_entry_action ***dst, size_t *n_dst, struct sfdo_hashmap *set) {
	struct sfdo_desktop_file_entry *entry;
	if ((entry = sfdo_desktop_file_group_get_entry(group, "Actions", 7)) == NULL) {
		*dst = NULL;
		*n_dst = 0;
		return SFDO_DESKTOP_ENTRY_LOAD_OK;
	}

	int line, column;
	sfdo_desktop_file_entry_get_location(entry, &line, &column);

	struct sfdo_desktop_db *db = loader->db;
	struct sfdo_logger *logger = &db->ctx->logger;

	const char *value = sfdo_desktop_file_entry_get_value(entry, NULL);

	size_t n_actions = 0;
	size_t id_start, id_len;
	size_t iter = 0;
	while ((sfdo_striter(value, ';', &iter, &id_start, &id_len))) {
		if (id_len > 0) {
			++n_actions;
		}
	}
	*n_dst = n_actions;

	struct sfdo_desktop_entry_action *actions_mem = NULL;
	struct sfdo_desktop_entry_action **actions = NULL;
	if (n_actions > 0) {
		actions_mem = calloc(n_actions, sizeof(*actions_mem));
		if (actions_mem == NULL) {
			logger_write_oom(logger);
			return SFDO_DESKTOP_ENTRY_LOAD_OOM;
		}
		actions = calloc(n_actions, sizeof(struct sfdo_desktop_entry_action *));
		if (actions == NULL) {
			free(actions_mem);
			logger_write_oom(logger);
			return SFDO_DESKTOP_ENTRY_LOAD_OOM;
		}
	}
	*dst_mem = actions_mem;
	*dst = actions;

	size_t action_i = 0;
	iter = 0;
	while ((sfdo_striter(value, ';', &iter, &id_start, &id_len))) {
		if (id_len > 0) {
			const char *id = value + id_start;
			struct sfdo_hashmap_entry *map_entry =
					sfdo_hashmap_get(set, value + id_start, id_len, true);
			if (map_entry == NULL) {
				logger_write_oom(logger);
				return SFDO_DESKTOP_ENTRY_LOAD_OOM;
			} else if (map_entry->key != NULL) {
				logger_write(logger, SFDO_LOG_LEVEL_ERROR, "%d:%d: duplicate action %s", line,
						column, map_entry->key);
				return SFDO_DESKTOP_ENTRY_LOAD_ERROR;
			}

			const char *owned = sfdo_strpool_add(&db->strings, id, id_len);
			if (owned == NULL) {
				logger_write_oom(logger);
				return SFDO_DESKTOP_ENTRY_LOAD_OOM;
			}
			map_entry->key = owned;

			struct sfdo_desktop_entry_action *action = &actions_mem[action_i];
			action->id.data = owned;
			action->id.len = id_len;

			actions[action_i] = action;
			++action_i;
		}
	}
	assert(action_i == n_actions);

	return SFDO_DESKTOP_ENTRY_LOAD_OK;
}

static bool exec_char_is_ws(char c) {
	return c == ' ' || c == '\t';
}

static bool exec_char_is_reserved(char c) {
	switch (c) {
	case ' ':
	case '\t':
	case '\n':
	case '"':
	case '\'':
	case '\\':
	case '>':
	case '<':
	case '~':
	case '|':
	case '&':
	case ';':
	case '$':
	case '*':
	case '?':
	case '#':
	case '(':
	case ')':
	case '`':
		return true;
	default:
		return false;
	}
}

static bool exec_char_needs_escape(char c) {
	switch (c) {
	case '"':
	case '`':
	case '$':
	case '\\':
		return true;
	default:
		return false;
	}
}

static bool exec_char_is_deprecated_field_code(char c) {
	switch (c) {
	case 'd':
	case 'D':
	case 'n':
	case 'N':
	case 'v':
	case 'm':
		return true;
	default:
		return false;
	}
}

static enum sfdo_desktop_entry_load_result exec_validate_character(
		struct sfdo_desktop_loader *loader, char c, bool quoted) {
	struct sfdo_desktop_db *db = loader->db;
	struct sfdo_logger *logger = &db->ctx->logger;
	struct sfdo_desktop_exec_scanner *scanner = &loader->exec;

	if (c == '=' && scanner->lit_buf_len == 0) {
		logger_write(logger, SFDO_LOG_LEVEL_ERROR,
				"%d:%d: unexpected \"=\" in the executable path at position %zu", scanner->line,
				scanner->column, scanner->i);
		return SFDO_DESKTOP_ENTRY_LOAD_ERROR;
	}

	if (quoted) {
		if (exec_char_needs_escape(c)) {
			logger_write(logger, SFDO_LOG_LEVEL_ERROR, "%d:%d: unescaped character at position %zu",
					scanner->line, scanner->column, scanner->i);
			return SFDO_DESKTOP_ENTRY_LOAD_ERROR;
		}
	} else {
		if (exec_char_is_reserved(c)) {
			logger_write(logger, SFDO_LOG_LEVEL_ERROR,
					"%d:%d: reserved character in a unquoted arg at position %zu", scanner->line,
					scanner->column, scanner->i);
			return SFDO_DESKTOP_ENTRY_LOAD_ERROR;
		}
	}

	return SFDO_DESKTOP_ENTRY_LOAD_OK;
}

static enum sfdo_desktop_entry_load_result exec_add_byte(
		struct sfdo_desktop_loader *loader, char c) {
	struct sfdo_desktop_db *db = loader->db;
	struct sfdo_logger *logger = &db->ctx->logger;
	struct sfdo_desktop_exec_scanner *scanner = &loader->exec;

	if (!sfdo_grow(&scanner->buf, &scanner->buf_cap, scanner->buf_len, 1)) {
		logger_write_oom(logger);
		return SFDO_DESKTOP_ENTRY_LOAD_OOM;
	}

	scanner->buf[scanner->buf_len++] = c;
	return SFDO_DESKTOP_ENTRY_LOAD_OK;
}

static enum sfdo_desktop_entry_load_result exec_add_string(
		struct sfdo_desktop_loader *loader, struct sfdo_string *str) {
	struct sfdo_desktop_db *db = loader->db;
	struct sfdo_logger *logger = &db->ctx->logger;
	struct sfdo_desktop_exec_scanner *scanner = &loader->exec;

	if (!sfdo_grow_n(&scanner->buf, &scanner->buf_cap, scanner->buf_len, 1, str->len)) {
		logger_write_oom(logger);
		return SFDO_DESKTOP_ENTRY_LOAD_OOM;
	}

	memcpy(&scanner->buf[scanner->buf_len], str->data, str->len);
	scanner->buf_len += str->len;

	return SFDO_DESKTOP_ENTRY_LOAD_OK;
}

static enum sfdo_desktop_entry_load_result exec_add_literal(
		struct sfdo_desktop_loader *loader, const char *literal) {
	struct sfdo_desktop_db *db = loader->db;
	struct sfdo_logger *logger = &db->ctx->logger;
	struct sfdo_desktop_exec_scanner *scanner = &loader->exec;

	if (!sfdo_grow(&scanner->lit_buf, &scanner->lit_buf_cap, scanner->lit_buf_len,
				sizeof(const char *))) {
		logger_write_oom(logger);
		return SFDO_DESKTOP_ENTRY_LOAD_OOM;
	}

	scanner->lit_buf[scanner->lit_buf_len++] = literal;
	return SFDO_DESKTOP_ENTRY_LOAD_OK;
}

static enum sfdo_desktop_entry_load_result exec_save_literal(struct sfdo_desktop_loader *loader) {
	struct sfdo_desktop_db *db = loader->db;
	struct sfdo_logger *logger = &db->ctx->logger;
	struct sfdo_desktop_exec_scanner *scanner = &loader->exec;

	enum sfdo_desktop_entry_load_result r = SFDO_DESKTOP_ENTRY_LOAD_OK;

	size_t len = scanner->buf_len;

	if ((r = exec_add_byte(loader, '\0')) != SFDO_DESKTOP_ENTRY_LOAD_OK) {
		return r;
	}

	const char *literal = sfdo_strpool_add(&db->strings, scanner->buf, len);
	if (literal == NULL) {
		logger_write_oom(logger);
		return SFDO_DESKTOP_ENTRY_LOAD_OOM;
	}

	return exec_add_literal(loader, literal);
}

static enum sfdo_desktop_entry_load_result exec_set_target(
		struct sfdo_desktop_loader *loader, char code) {
	struct sfdo_desktop_db *db = loader->db;
	struct sfdo_logger *logger = &db->ctx->logger;
	struct sfdo_desktop_exec_scanner *scanner = &loader->exec;

	struct sfdo_desktop_exec *dst = scanner->dst;

	if (dst->target_i != (size_t)-1) {
		logger_write(logger, SFDO_LOG_LEVEL_ERROR,
				"%d:%d: a command line must not have multiple target field codes", scanner->line,
				scanner->column);
		return SFDO_DESKTOP_ENTRY_LOAD_ERROR;
	}
	dst->target_i = scanner->lit_buf_len;

	dst->supports_uri = code == 'u' || code == 'U';
	dst->supports_list = code == 'F' || code == 'U';

	return SFDO_DESKTOP_ENTRY_LOAD_OK;
}

static enum sfdo_desktop_entry_load_result exec_add_quoted(struct sfdo_desktop_loader *loader) {
	struct sfdo_desktop_db *db = loader->db;
	struct sfdo_logger *logger = &db->ctx->logger;
	struct sfdo_desktop_exec_scanner *scanner = &loader->exec;

	enum sfdo_desktop_entry_load_result r = SFDO_DESKTOP_ENTRY_LOAD_OK;

	size_t start_i = scanner->i;
	++scanner->i; // Skip the opening quote

	char escape = '\0';
	size_t escape_i;
	while (true) {
		if (scanner->i == scanner->data_len) {
			logger_write(logger, SFDO_LOG_LEVEL_ERROR, "%d:%d: unclosed quote at position %zu",
					scanner->line, scanner->column, start_i);
			return SFDO_DESKTOP_ENTRY_LOAD_ERROR;
		}
		char c = scanner->data[scanner->i];

		if (escape != '\0') {
			if (escape == '\\') {
				if (!exec_char_needs_escape(c)) {
					logger_write(logger, SFDO_LOG_LEVEL_ERROR,
							"%d:%d: invalid escape sequence at position %zu", scanner->line,
							scanner->column, escape_i);
					return SFDO_DESKTOP_ENTRY_LOAD_ERROR;
				}
			} else if (escape == '%') {
				if (c != '%') {
					logger_write(logger, SFDO_LOG_LEVEL_ERROR,
							"%d:%d: unexpected field code in a quoted argument at position %zu",
							scanner->line, scanner->column, escape_i);
					return SFDO_DESKTOP_ENTRY_LOAD_ERROR;
				}
			} else {
				assert(false);
			}
			escape = '\0';

			if ((r = exec_add_byte(loader, c)) != SFDO_DESKTOP_ENTRY_LOAD_OK) {
				return r;
			}
		} else if (c == '"') {
			break;
		} else if (c == '\\' || c == '%') {
			escape = c;
			escape_i = scanner->i;
		} else if ((r = exec_validate_character(loader, c, true)) != SFDO_DESKTOP_ENTRY_LOAD_OK) {
			return r;
		} else {
			if ((r = exec_add_byte(loader, c)) != SFDO_DESKTOP_ENTRY_LOAD_OK) {
				return r;
			}
		}

		++scanner->i;
	}

	if ((r = exec_save_literal(loader)) != SFDO_DESKTOP_ENTRY_LOAD_OK) {
		return r;
	}

	++scanner->i; // Skip the closing quote

	return SFDO_DESKTOP_ENTRY_LOAD_OK;
}

static bool exec_try_consume_standalone(struct sfdo_desktop_exec_scanner *scanner, char *code) {
	const char *exec = scanner->data;
	size_t i = scanner->i;
	size_t len = scanner->data_len;
	if (len - i < 2 || exec[i] != '%') {
		return false;
	}
	*code = exec[i + 1];
	if (len - i > 2 && !exec_char_is_ws(exec[i + 2])) {
		// Followed by a non-whitespace character
		return false;
	}
	scanner->i += 2;
	return true;
}

static enum sfdo_desktop_entry_load_result exec_add_unquoted(struct sfdo_desktop_loader *loader) {
	struct sfdo_desktop_db *db = loader->db;
	struct sfdo_logger *logger = &db->ctx->logger;
	struct sfdo_desktop_exec_scanner *scanner = &loader->exec;

	struct sfdo_desktop_entry *entry = scanner->entry;

	enum sfdo_desktop_entry_load_result r = SFDO_DESKTOP_ENTRY_LOAD_OK;

	size_t field_i = scanner->i;

	char standalone = '\0';
	if (exec_try_consume_standalone(scanner, &standalone)) {
		switch (standalone) {
		case 'f':
		case 'u':
		case 'F':
		case 'U':
			if ((r = exec_set_target(loader, standalone)) != SFDO_DESKTOP_ENTRY_LOAD_OK) {
				return r;
			}
			break;
		case 'i':
			if (scanner->entry->icon.data != NULL) {
				if ((r = exec_add_literal(loader, "--icon")) != SFDO_DESKTOP_ENTRY_LOAD_OK) {
					return r;
				}
				if ((r = exec_add_literal(loader, entry->icon.data)) !=
						SFDO_DESKTOP_ENTRY_LOAD_OK) {
					return r;
				}
			}
			break;
		case '%':
			if ((r = exec_add_literal(loader, "%")) != SFDO_DESKTOP_ENTRY_LOAD_OK) {
				return r;
			}
			break;
		case 'c':
			if ((r = exec_add_literal(loader, entry->name.data)) != SFDO_DESKTOP_ENTRY_LOAD_OK) {
				return r;
			}
			break;
		case 'k':
			if ((r = exec_add_literal(loader, entry->file_path.data)) !=
					SFDO_DESKTOP_ENTRY_LOAD_OK) {
				return r;
			}
			break;
		default:
			if (!exec_char_is_deprecated_field_code(standalone)) {
				goto err_invalid_field_code;
			}
			if ((r = exec_add_literal(loader, "")) != SFDO_DESKTOP_ENTRY_LOAD_OK) {
				return r;
			}
			break;
		}
		return SFDO_DESKTOP_ENTRY_LOAD_OK;
	}

	struct sfdo_desktop_exec *dst = scanner->dst;

	bool field = false;
	bool has_target = false;
	while (scanner->i < scanner->data_len) {
		char c = scanner->data[scanner->i];
		if (field) {
			field = false;
			switch (c) {
			case 'f':
			case 'u':
				if ((r = exec_set_target(loader, c)) != SFDO_DESKTOP_ENTRY_LOAD_OK) {
					return r;
				}
				assert(!has_target);
				assert(dst->embed.before == 0 && dst->embed.after == 0);
				has_target = true;
				dst->embed.before = scanner->buf_len;
				break;
			case 'F':
			case 'U':
			case 'i':
				logger_write(logger, SFDO_LOG_LEVEL_ERROR,
						"%d:%d: field code at position %zu must be standalone", scanner->line,
						scanner->column, field_i);
				return SFDO_DESKTOP_ENTRY_LOAD_ERROR;
			case '%':
				if ((r = exec_add_byte(loader, c)) != SFDO_DESKTOP_ENTRY_LOAD_OK) {
					return r;
				}
				break;
			case 'c':
				if ((r = exec_add_string(loader, &entry->name)) != SFDO_DESKTOP_ENTRY_LOAD_OK) {
					return r;
				}
				break;
			case 'k':
				if ((r = exec_add_string(loader, &entry->file_path)) !=
						SFDO_DESKTOP_ENTRY_LOAD_OK) {
					return r;
				}
				break;
			default:
				if (!exec_char_is_deprecated_field_code(standalone)) {
					goto err_invalid_field_code;
				}
				break;
			}
		} else if (exec_char_is_ws(c)) {
			break;
		} else if (c == '%') {
			field = true;
			field_i = scanner->i;
		} else if ((r = exec_validate_character(loader, c, false)) != SFDO_DESKTOP_ENTRY_LOAD_OK) {
			return r;
		} else {
			if ((r = exec_add_byte(loader, c)) != SFDO_DESKTOP_ENTRY_LOAD_OK) {
				return r;
			}
		}

		++scanner->i;
	}

	if (field) {
		logger_write(logger, SFDO_LOG_LEVEL_ERROR, "%d:%d: truncated field code at position %zu",
				scanner->line, scanner->column, field_i);
		return SFDO_DESKTOP_ENTRY_LOAD_ERROR;
	}

	if (has_target) {
		dst->embed.after = scanner->buf_len - dst->embed.before;
		assert(dst->embed.before != 0 || dst->embed.after != 0);
	}

	if ((r = exec_save_literal(loader)) != SFDO_DESKTOP_ENTRY_LOAD_OK) {
		return r;
	}

	return SFDO_DESKTOP_ENTRY_LOAD_OK;

err_invalid_field_code:
	logger_write(logger, SFDO_LOG_LEVEL_ERROR, "%d:%d: invalid field code at position %zu",
			scanner->line, scanner->column, field_i);
	return SFDO_DESKTOP_ENTRY_LOAD_ERROR;
}

static bool exec_find_arg(struct sfdo_desktop_exec_scanner *scanner) {
	while (true) {
		if (scanner->i == scanner->data_len) {
			return false;
		} else if (!exec_char_is_ws(scanner->data[scanner->i])) {
			return true;
		}
		++scanner->i;
	}
}

static void exec_scanner_start(struct sfdo_desktop_exec_scanner *scanner,
		struct sfdo_desktop_file_entry *file_entry, struct sfdo_desktop_entry *entry,
		struct sfdo_desktop_exec *dst) {
	scanner->entry = entry;

	scanner->data = sfdo_desktop_file_entry_get_value(file_entry, &scanner->data_len);
	sfdo_desktop_file_entry_get_location(file_entry, &scanner->line, &scanner->column);

	scanner->dst = dst;

	scanner->i = 0;

	scanner->buf_len = 0;
	scanner->lit_buf_len = 0;

	*dst = (struct sfdo_desktop_exec){
		.literals = NULL,
		.target_i = (size_t)-1,
	};
}

static enum sfdo_desktop_entry_load_result load_exec(struct sfdo_desktop_loader *loader,
		struct sfdo_desktop_file_entry *file_entry, struct sfdo_desktop_entry *entry,
		struct sfdo_desktop_exec *dst) {
	struct sfdo_desktop_db *db = loader->db;
	struct sfdo_logger *logger = &db->ctx->logger;
	struct sfdo_desktop_exec_scanner *scanner = &loader->exec;

	exec_scanner_start(scanner, file_entry, entry, dst);

	enum sfdo_desktop_entry_load_result r = SFDO_DESKTOP_ENTRY_LOAD_OK;

	while (exec_find_arg(scanner)) {
		scanner->buf_len = 0;

		if (scanner->data[scanner->i] == '"') {
			r = exec_add_quoted(loader);
		} else {
			r = exec_add_unquoted(loader);
		}

		if (r != SFDO_DESKTOP_ENTRY_LOAD_OK) {
			return r;
		}
	}

	dst->n_literals = scanner->lit_buf_len;
	dst->literals = calloc(dst->n_literals, sizeof(const char *));
	if (dst->literals == NULL) {
		logger_write_oom(logger);
		return SFDO_DESKTOP_ENTRY_LOAD_OOM;
	}

	memcpy(dst->literals, scanner->lit_buf, sizeof(const char *) * dst->n_literals);
	return SFDO_DESKTOP_ENTRY_LOAD_OK;
}

static enum sfdo_desktop_entry_load_result load_show_in(struct sfdo_desktop_loader *loader,
		struct sfdo_desktop_file_group *group, struct sfdo_desktop_entry *d_entry) {
	struct sfdo_desktop_db *db = loader->db;
	struct sfdo_logger *logger = &db->ctx->logger;

	struct sfdo_desktop_file_entry *yes_entry =
			sfdo_desktop_file_group_get_entry(group, "OnlyShowIn", 10);
	struct sfdo_desktop_file_entry *no_entry =
			sfdo_desktop_file_group_get_entry(group, "NotShowIn", 9);

	const struct sfdo_string *items;
	size_t n_items;

	enum sfdo_desktop_entry_load_result r = SFDO_DESKTOP_ENTRY_LOAD_OK;

	if (yes_entry != NULL) {
		d_entry->default_show = false;
		items = sfdo_desktop_file_entry_get_value_list(yes_entry, &n_items);
		if ((r = store_list(loader, items, n_items, &d_entry->show_exceptions,
					 &d_entry->n_show_exceptions)) != SFDO_DESKTOP_ENTRY_LOAD_OK) {
			return r;
		}
		if (no_entry != NULL) {
			items = sfdo_desktop_file_entry_get_value_list(no_entry, &n_items);
			// XXX: this is O(n²) but also never happens in practice so whatever
			for (size_t no_i = 0; no_i < n_items; no_i++) {
				const struct sfdo_string *no = &items[no_i];
				for (size_t yes_i = 0; yes_i < d_entry->n_show_exceptions; yes_i++) {
					struct sfdo_string *yes = &d_entry->show_exceptions[yes_i];
					if (yes->len == no->len && memcmp(yes->data, no->data, yes->len) == 0) {
						int group_line, group_column;
						sfdo_desktop_file_group_get_location(group, &group_line, &group_column);
						logger_write(logger, SFDO_LOG_LEVEL_ERROR,
								"%d:%d: %s is both in OnlyShowIn and NotShowIn", group_line,
								group_column, yes->data);
						return SFDO_DESKTOP_ENTRY_LOAD_ERROR;
					}
				}
			}
		}
	} else {
		d_entry->default_show = true;
		if (no_entry != NULL) {
			items = sfdo_desktop_file_entry_get_value_list(no_entry, &n_items);
			if ((r = store_list(loader, items, n_items, &d_entry->show_exceptions,
						 &d_entry->n_show_exceptions)) != SFDO_DESKTOP_ENTRY_LOAD_OK) {
				return r;
			}
		}
	}

	return SFDO_DESKTOP_ENTRY_LOAD_OK;
}

static bool dbus_name_char_is_valid_leader(char c, bool allow_hyphen) {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' ||
			(allow_hyphen && c == '-');
}

static bool dbus_name_char_is_valid_cont(char c, bool allow_hyphen) {
	return (c >= '0' && c <= '9') || dbus_name_char_is_valid_leader(c, allow_hyphen);
}

static bool validate_dbus_name(const char *name, size_t len, bool interface) {
	if (len > 255) {
		// Exceeds maximum name length
		return false;
	}

	int n_elements = 0;
	size_t elem_start, elem_len;
	size_t iter = 0;
	while (sfdo_striter(name, '.', &iter, &elem_start, &elem_len)) {
		if (elem_len == 0) {
			// All elements must contain at least one character
			return false;
		}
		if (!dbus_name_char_is_valid_leader(name[elem_start], !interface)) {
			return false;
		}
		for (size_t i = 1; i < elem_len; i++) {
			if (!dbus_name_char_is_valid_cont(name[elem_start + i], !interface)) {
				return false;
			}
		}
		++n_elements;
	}

	if (interface && n_elements < 2) {
		// Interface names are composed of 2 or more elements
		return false;
	}

	return true;
}

static enum sfdo_desktop_entry_load_result entry_load(struct sfdo_desktop_loader *loader,
		struct sfdo_desktop_file_document *doc, struct sfdo_desktop_map_entry *map_entry) {
	struct sfdo_desktop_db *db = loader->db;
	struct sfdo_logger *logger = &db->ctx->logger;

	const char *group_name;
	size_t group_name_len;

	struct sfdo_desktop_file_entry *entry;

	const char *value;
	size_t value_len;

	const struct sfdo_string *items;
	size_t n_items;

	int group_line, group_column;
	struct sfdo_desktop_file_group *group = sfdo_desktop_file_document_get_groups(doc);

	if (group == NULL) {
		logger_write(logger, SFDO_LOG_LEVEL_ERROR, "Expected \"Desktop Entry\" group");
		return SFDO_DESKTOP_ENTRY_LOAD_ERROR;
	}

	sfdo_desktop_file_group_get_location(group, &group_line, &group_column);

	group_name = sfdo_desktop_file_group_get_name(group, &group_name_len);
	if (strcmp(group_name, "Desktop Entry") != 0) {
		logger_write(logger, SFDO_LOG_LEVEL_ERROR,
				"%d:%d: expected \"Desktop Entry\" group, got \"%s\"", group_line, group_column,
				group_name);
		return SFDO_DESKTOP_ENTRY_LOAD_ERROR;
	}

	enum sfdo_desktop_entry_type type;
	if ((entry = sfdo_desktop_file_group_get_entry(group, "Type", 4)) != NULL) {
		value = sfdo_desktop_file_entry_get_value(entry, &value_len);
		if (strcmp(value, "Application") == 0) {
			type = SFDO_DESKTOP_ENTRY_APPLICATION;
		} else if (strcmp(value, "Link") == 0) {
			type = SFDO_DESKTOP_ENTRY_LINK;
		} else if (strcmp(value, "Directory") == 0) {
			type = SFDO_DESKTOP_ENTRY_DIRECTORY;
		} else {
			logger_write(logger, SFDO_LOG_LEVEL_INFO, "Skipping %s of unknown Type \"%s\"",
					loader->id_buf.data, value);
			return SFDO_DESKTOP_ENTRY_LOAD_OK;
		}
	} else {
		logger_write(
				logger, SFDO_LOG_LEVEL_ERROR, "%d:%d: Type is unset", group_line, group_column);
		return SFDO_DESKTOP_ENTRY_LOAD_ERROR;
	}

	enum sfdo_desktop_entry_load_result r = SFDO_DESKTOP_ENTRY_LOAD_OK;

	bool hidden;
	if ((r = load_boolean(loader, group, "Hidden", 6, &hidden)) != SFDO_DESKTOP_ENTRY_LOAD_OK) {
		return r;
	}
	if (hidden) {
		logger_write(logger, SFDO_LOG_LEVEL_DEBUG, "Skipping hidden entry %s", map_entry->base.key);
		return SFDO_DESKTOP_ENTRY_LOAD_OK;
	}

	// The desktop entry isn't skipped immediately

	struct sfdo_desktop_entry *d_entry = calloc(1, sizeof(*d_entry));
	if (d_entry == NULL) {
		logger_write_oom(logger);
		return SFDO_DESKTOP_ENTRY_LOAD_OOM;
	}
	d_entry->type = type;

	struct sfdo_hashmap action_set;
	sfdo_hashmap_init(&action_set, sizeof(struct sfdo_hashmap_entry));

	d_entry->id.data = map_entry->base.key;
	d_entry->id.len = map_entry->base.key_len;

	if ((r = store_string(loader, loader->path_buf.data, loader->path_buf.len,
				 &d_entry->file_path)) != SFDO_DESKTOP_ENTRY_LOAD_OK) {
		goto end;
	}

	if ((r = load_string(loader, group, "Name", 4, SFDO_DESKTOP_ENTRY_VALUE_REQUIRED,
				 SFDO_DESKTOP_ENTRY_VALUE_LOCALESTRING, &d_entry->name)) !=
			SFDO_DESKTOP_ENTRY_LOAD_OK) {
		goto end;
	}
	if ((r = load_boolean(loader, group, "NoDisplay", 9, &d_entry->no_display)) !=
			SFDO_DESKTOP_ENTRY_LOAD_OK) {
		goto end;
	}
	if ((r = load_string(loader, group, "GenericName", 11, SFDO_DESKTOP_ENTRY_VALUE_OPTIONAL,
				 SFDO_DESKTOP_ENTRY_VALUE_LOCALESTRING, &d_entry->generic_name)) !=
			SFDO_DESKTOP_ENTRY_LOAD_OK) {
		goto end;
	}
	if ((r = load_string(loader, group, "Comment", 7, SFDO_DESKTOP_ENTRY_VALUE_OPTIONAL,
				 SFDO_DESKTOP_ENTRY_VALUE_LOCALESTRING, &d_entry->comment)) !=
			SFDO_DESKTOP_ENTRY_LOAD_OK) {
		goto end;
	}
	if ((r = load_string(loader, group, "Icon", 4, SFDO_DESKTOP_ENTRY_VALUE_OPTIONAL,
				 SFDO_DESKTOP_ENTRY_VALUE_LOCALESTRING, &d_entry->icon)) !=
			SFDO_DESKTOP_ENTRY_LOAD_OK) {
		goto end;
	}

	if ((r = load_show_in(loader, group, d_entry)) != SFDO_DESKTOP_ENTRY_LOAD_OK) {
		goto end;
	}

	if ((entry = sfdo_desktop_file_group_get_entry(group, "Implements", 10)) != NULL) {
		items = sfdo_desktop_file_entry_get_value_list(entry, &n_items);
		if ((r = store_list(loader, items, n_items, &d_entry->implements,
					 &d_entry->n_implements)) != SFDO_DESKTOP_ENTRY_LOAD_OK) {
			goto end;
		}
		for (size_t i = 0; i < d_entry->n_implements; i++) {
			struct sfdo_string *iface = &d_entry->implements[i];
			if (!validate_dbus_name(iface->data, iface->len, true)) {
				int line, column;
				sfdo_desktop_file_entry_get_location(entry, &line, &column);
				logger_write(logger, SFDO_LOG_LEVEL_ERROR, "%d:%d: %s is not a valid D-Bus name",
						line, column, iface->data);
				r = SFDO_DESKTOP_ENTRY_LOAD_ERROR;
				goto end;
			}
		}
	}

	bool startup_notify;
	bool has_startup_notify;

	size_t action_i = 0;

	switch (type) {
	case SFDO_DESKTOP_ENTRY_APPLICATION:
		if ((r = load_optional_boolean(loader, group, "StartupNotify", 13, &startup_notify,
					 &has_startup_notify)) != SFDO_DESKTOP_ENTRY_LOAD_OK) {
			goto end;
		}
		d_entry->app.startup_notify = has_startup_notify
				? startup_notify ? SFDO_DESKTOP_ENTRY_STARTUP_NOTIFY_TRUE
								 : SFDO_DESKTOP_ENTRY_STARTUP_NOTIFY_FALSE
				: SFDO_DESKTOP_ENTRY_STARTUP_NOTIFY_UNKNOWN;
		if ((r = load_boolean(loader, group, "DBusActivatable", 15,
					 &d_entry->app.dbus_activatable)) != SFDO_DESKTOP_ENTRY_LOAD_OK) {
			goto end;
		}
		if (d_entry->app.dbus_activatable) {
			if (!validate_dbus_name(d_entry->id.data, d_entry->id.len, false)) {
				logger_write(logger, SFDO_LOG_LEVEL_ERROR,
						"%d:%d: DBusActivatable is true but %s is not a valid D-Bus name",
						group_line, group_column, d_entry->id.data);
				r = SFDO_DESKTOP_ENTRY_LOAD_ERROR;
				goto end;
			}
		}
		if ((r = load_boolean(loader, group, "Terminal", 8, &d_entry->app.terminal)) !=
				SFDO_DESKTOP_ENTRY_LOAD_OK) {
			goto end;
		}
		if ((r = load_boolean(loader, group, "PrefersNonDefaultGPU", 20,
					 &d_entry->app.prefers_non_default_gpu)) != SFDO_DESKTOP_ENTRY_LOAD_OK) {
			goto end;
		}
		if ((r = load_boolean(loader, group, "SingleMainWindow", 16,
					 &d_entry->app.single_main_window)) != SFDO_DESKTOP_ENTRY_LOAD_OK) {
			goto end;
		}
		if ((r = load_string(loader, group, "TryExec", 7, SFDO_DESKTOP_ENTRY_VALUE_OPTIONAL,
					 SFDO_DESKTOP_ENTRY_VALUE_STRING, &d_entry->app.try_exec)) !=
				SFDO_DESKTOP_ENTRY_LOAD_OK) {
			goto end;
		}
		if ((entry = sfdo_desktop_file_group_get_entry(group, "Exec", 4)) != NULL) {
			if ((r = load_exec(loader, entry, d_entry, &d_entry->app.exec)) !=
					SFDO_DESKTOP_ENTRY_LOAD_OK) {
				goto end;
			}
		} else if (!d_entry->app.dbus_activatable) {
			logger_write(logger, SFDO_LOG_LEVEL_ERROR,
					"%d:%d: Exec is unset while DBusActivatable is unset or false", group_line,
					group_column);
			r = SFDO_DESKTOP_ENTRY_LOAD_ERROR;
			goto end;
		}
		if ((r = load_string(loader, group, "Path", 4, SFDO_DESKTOP_ENTRY_VALUE_OPTIONAL,
					 SFDO_DESKTOP_ENTRY_VALUE_STRING, &d_entry->app.path)) !=
				SFDO_DESKTOP_ENTRY_LOAD_OK) {
			goto end;
		}
		if ((r = load_string(loader, group, "StartupWMClass", 14, SFDO_DESKTOP_ENTRY_VALUE_OPTIONAL,
					 SFDO_DESKTOP_ENTRY_VALUE_STRING, &d_entry->app.startup_wm_class)) !=
				SFDO_DESKTOP_ENTRY_LOAD_OK) {
			goto end;
		}
		if ((r = load_list(loader, group, "MimeType", 8, SFDO_DESKTOP_ENTRY_VALUE_STRING,
					 &d_entry->app.mimetypes, &d_entry->app.n_mimetypes)) !=
				SFDO_DESKTOP_ENTRY_LOAD_OK) {
			goto end;
		}
		if ((r = load_actions(loader, group, &d_entry->app.actions_mem, &d_entry->app.actions,
					 &d_entry->app.n_actions, &action_set)) != SFDO_DESKTOP_ENTRY_LOAD_OK) {
			goto end;
		}
		if ((r = load_list(loader, group, "Categories", 10, SFDO_DESKTOP_ENTRY_VALUE_STRING,
					 &d_entry->app.categories, &d_entry->app.n_categories)) !=
				SFDO_DESKTOP_ENTRY_LOAD_OK) {
			goto end;
		}
		if ((r = load_list(loader, group, "Keywords", 8, SFDO_DESKTOP_ENTRY_VALUE_LOCALESTRING,
					 &d_entry->app.keywords, &d_entry->app.n_keywords)) !=
				SFDO_DESKTOP_ENTRY_LOAD_OK) {
			goto end;
		}

		for (group = sfdo_desktop_file_group_get_next(group); group != NULL;
				group = sfdo_desktop_file_group_get_next(group)) {
			group_name = sfdo_desktop_file_group_get_name(group, &group_name_len);
			if (strncmp(group_name, DESKTOP_ACTION_PREFIX, sizeof(DESKTOP_ACTION_PREFIX) - 1) !=
					0) {
				// Unknown group
				continue;
			}

			sfdo_desktop_file_group_get_location(group, &group_line, &group_column);

			size_t action_id_len = group_name_len - sizeof(DESKTOP_ACTION_PREFIX) + 1;
			const char *action_id = group_name + sizeof(DESKTOP_ACTION_PREFIX) - 1;
			if (sfdo_hashmap_get(&action_set, action_id, action_id_len, false) == NULL) {
				// "It is not valid to have an action group for an action identifier not mentioned
				// in the Actions key. Such an action group must be ignored by implementors."
				logger_write(
						logger, SFDO_LOG_LEVEL_ERROR, "Ignoring unknown action %s", group_name);
				continue;
			}

			assert(action_i < d_entry->app.n_actions);
			struct sfdo_desktop_entry_action *action = d_entry->app.actions[action_i++];

			if ((r = load_string(loader, group, "Name", 4, SFDO_DESKTOP_ENTRY_VALUE_REQUIRED,
						 SFDO_DESKTOP_ENTRY_VALUE_LOCALESTRING, &action->name)) !=
					SFDO_DESKTOP_ENTRY_LOAD_OK) {
				goto end;
			}
			if ((r = load_string(loader, group, "Icon", 4, SFDO_DESKTOP_ENTRY_VALUE_OPTIONAL,
						 SFDO_DESKTOP_ENTRY_VALUE_LOCALESTRING, &action->icon)) !=
					SFDO_DESKTOP_ENTRY_LOAD_OK) {
				goto end;
			}
			if ((entry = sfdo_desktop_file_group_get_entry(group, "Exec", 4)) != NULL) {
				if ((r = load_exec(loader, entry, d_entry, &action->exec)) !=
						SFDO_DESKTOP_ENTRY_LOAD_OK) {
					goto end;
				}
			} else if (!d_entry->app.dbus_activatable) {
				logger_write(logger, SFDO_LOG_LEVEL_ERROR,
						"%d:%d: Exec is unset while DBusActivatable is unset or false", group_line,
						group_column);
				r = SFDO_DESKTOP_ENTRY_LOAD_ERROR;
				goto end;
			}
		}

		if (action_i != d_entry->app.n_actions) {
			logger_write(logger, SFDO_LOG_LEVEL_ERROR, "Found only %zu action groups out of %zu",
					action_i, d_entry->app.n_actions);
			r = SFDO_DESKTOP_ENTRY_LOAD_ERROR;
			goto end;
		}

		break;
	case SFDO_DESKTOP_ENTRY_LINK:
		if ((r = load_string(loader, group, "URL", 3, SFDO_DESKTOP_ENTRY_VALUE_REQUIRED,
					 SFDO_DESKTOP_ENTRY_VALUE_STRING, &d_entry->link.url)) !=
				SFDO_DESKTOP_ENTRY_LOAD_OK) {
			goto end;
		}
		break;
	case SFDO_DESKTOP_ENTRY_DIRECTORY:
		break;
	}

end:
	sfdo_hashmap_finish(&action_set);
	if (r == SFDO_DESKTOP_ENTRY_LOAD_OK) {
		map_entry->entry = d_entry;
	} else {
		desktop_entry_destroy(d_entry);
	}
	return r;
}

static bool scan_dir(struct sfdo_desktop_loader *loader, size_t basedir_len) {
	struct sfdo_desktop_db *db = loader->db;
	struct sfdo_logger *logger = &db->ctx->logger;
	struct sfdo_strbuild *pb = &loader->path_buf;
	struct sfdo_strbuild *ib = &loader->id_buf;

	DIR *dirp = opendir(pb->data);
	if (dirp == NULL) {
		return true;
	}

	logger_write(logger, SFDO_LOG_LEVEL_DEBUG, "Scanning dir %s", pb->data);

	size_t base_pb_len = pb->len;
	size_t base_id_len = ib->len;

	bool ok = false;

	struct dirent *dirent;
	while ((dirent = readdir(dirp)) != NULL) {
		char *name = dirent->d_name;
		if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
			continue;
		}

		size_t name_len = strlen(name);

		pb->len = base_pb_len;
		if (!sfdo_strbuild_add(pb, name, name_len, NULL)) {
			logger_write_oom(logger);
			goto end;
		}

		ib->len = base_id_len;

		struct stat statbuf;
		if (stat(pb->data, &statbuf) != 0) {
			continue;
		}

		if (S_ISDIR(statbuf.st_mode)) {
			if (!sfdo_strbuild_add(ib, name, name_len, "-", 1, NULL)) {
				logger_write_oom(logger);
				goto end;
			}
			if (!sfdo_strbuild_add(pb, "/", 1, NULL)) {
				logger_write_oom(logger);
				goto end;
			}
			if (!scan_dir(loader, basedir_len)) {
				goto end;
			}

			continue;
		}

		size_t suffix_len = 0;
		const char *name_end = name + name_len + 1;
		if (name_len > sizeof(ENTRY_DESKTOP_SUFFIX) &&
				strcmp(name_end - sizeof(ENTRY_DESKTOP_SUFFIX), ENTRY_DESKTOP_SUFFIX) == 0) {
			suffix_len = sizeof(ENTRY_DESKTOP_SUFFIX) - 1;
		} else if (name_len > sizeof(ENTRY_DIRECTORY_SUFFIX) &&
				strcmp(name_end - sizeof(ENTRY_DIRECTORY_SUFFIX), ENTRY_DIRECTORY_SUFFIX) == 0) {
			suffix_len = sizeof(ENTRY_DIRECTORY_SUFFIX) - 1;
		} else {
			// If there's any other extension (/(.*\).(.+)/), skip the file; otherwise, try to read
			// it anyway, or as the spec calls it, "fall back to recognition via 'magic detection'".
			bool has_ext = false;
			for (size_t i = 0; i < name_len - 1; i++) {
				if (name[i] == '.') {
					has_ext = true;
					break;
				}
			}
			if (has_ext) {
				continue;
			}
		}

		if (!sfdo_strbuild_add(ib, name, name_len - suffix_len, NULL)) {
			logger_write_oom(logger);
			goto end;
		}

		struct sfdo_desktop_map_entry *map_entry =
				sfdo_hashmap_get(&db->entries, ib->data, ib->len, true);
		if (map_entry == NULL) {
			logger_write_oom(logger);
			goto end;
		} else if (map_entry->base.key != NULL) {
			// Add only the first one
			continue;
		} else {
			map_entry->base.key = sfdo_strpool_add(&db->strings, ib->data, ib->len);
			if (map_entry->base.key == NULL) {
				logger_write_oom(logger);
				goto end;
			}
		}

		FILE *fp = fopen(pb->data, "r");
		if (fp == NULL) {
			logger_write(logger, SFDO_LOG_LEVEL_ERROR, "Failed to open %s: %s", pb->data,
					strerror(errno));
			continue;
		}

		struct sfdo_desktop_file_error desktop_file_error;
		struct sfdo_desktop_file_document *doc = sfdo_desktop_file_document_load(
				fp, loader->locale, SFDO_DESKTOP_FILE_LOAD_OPTIONS_DEFAULT, &desktop_file_error);
		fclose(fp);

		if (doc != NULL) {
			// Avoid storing strings for entries we end up ignoring due to bad format
			struct sfdo_strpool_state strings_state;
			sfdo_strpool_save(&db->strings, &strings_state);

			enum sfdo_desktop_entry_load_result result = entry_load(loader, doc, map_entry);
			sfdo_desktop_file_document_destroy(doc);

			switch (result) {
			case SFDO_DESKTOP_ENTRY_LOAD_OK:
				if (map_entry->entry != NULL) {
					logger_write(logger, SFDO_LOG_LEVEL_DEBUG, "Loaded entry %s", ib->data);
					++loader->n_entries;
				}
				continue;
			case SFDO_DESKTOP_ENTRY_LOAD_ERROR:
				sfdo_strpool_restore(&db->strings, &strings_state);
				break;
			case SFDO_DESKTOP_ENTRY_LOAD_OOM:
				goto end;
			}
		} else {
			logger_write(logger, SFDO_LOG_LEVEL_ERROR, "%d:%d: %s", desktop_file_error.line,
					desktop_file_error.column,
					sfdo_desktop_file_error_code_get_description(desktop_file_error.code));
		}

		logger_write(logger, SFDO_LOG_LEVEL_ERROR, "Failed to load %s", pb->data);
	}

	ok = true;

end:
	closedir(dirp);
	return ok;
}

static struct sfdo_desktop_db *db_create(
		struct sfdo_desktop_ctx *ctx, const struct sfdo_string *basedirs, size_t n_basedirs) {
	struct sfdo_desktop_db *db = calloc(1, sizeof(*db));
	if (db == NULL) {
		goto err_db;
	}

	if (!sfdo_dirs_store(basedirs, n_basedirs, &db->basedirs, &db->n_basedirs, &db->basedirs_mem)) {
		goto err_dirs;
	}

	db->ctx = ctx;

	sfdo_hashmap_init(&db->entries, sizeof(struct sfdo_desktop_map_entry));
	sfdo_strpool_init(&db->strings);

	return db;

err_dirs:
	free(db);
err_db:
	logger_write_oom(&ctx->logger);
	return NULL;
}

SFDO_API struct sfdo_desktop_db *sfdo_desktop_db_load(
		struct sfdo_desktop_ctx *ctx, const char *locale) {
	return sfdo_desktop_db_load_from(ctx, locale, ctx->default_basedirs, ctx->default_n_basedirs);
}

SFDO_API struct sfdo_desktop_db *sfdo_desktop_db_load_from(struct sfdo_desktop_ctx *ctx,
		const char *locale, const struct sfdo_string *basedirs, size_t n_basedirs) {
	struct sfdo_desktop_db *db = db_create(ctx, basedirs, n_basedirs);
	if (db == NULL) {
		return NULL;
	}

	struct sfdo_desktop_loader loader = {
		.db = db,
		.locale = locale,
	};

	struct sfdo_strbuild *pb = &loader.path_buf;
	struct sfdo_strbuild *ib = &loader.id_buf;

	sfdo_strbuild_init(pb);
	sfdo_strbuild_init(ib);

	bool ok = false;

	for (size_t basedir_i = 0; basedir_i < db->n_basedirs; basedir_i++) {
		struct sfdo_string *basedir = &db->basedirs[basedir_i];
		sfdo_strbuild_reset(pb);
		sfdo_strbuild_reset(ib);
		if (!sfdo_strbuild_add(pb, basedir->data, basedir->len, NULL)) {
			logger_write_oom(&db->ctx->logger);
			goto end;
		}
		if (!scan_dir(&loader, basedir->len)) {
			goto end;
		}
	}

	if (loader.n_entries > 0) {
		db->entries_list = calloc(loader.n_entries, sizeof(struct sfdo_desktop_entry *));
		if (db->entries_list == NULL) {
			logger_write_oom(&db->ctx->logger);
			goto end;
		}
	}
	db->n_entries = loader.n_entries;

	struct sfdo_hashmap *entries = &db->entries;
	size_t list_i = 0;
	for (size_t i = 0; i < entries->cap; i++) {
		struct sfdo_desktop_map_entry *map_entry =
				&((struct sfdo_desktop_map_entry *)entries->mem)[i];
		if (map_entry->base.key != NULL && map_entry->entry != NULL) {
			db->entries_list[list_i++] = map_entry->entry;
		}
	}
	assert(list_i == db->n_entries);

	ok = true;

end:
	sfdo_strbuild_finish(pb);
	sfdo_strbuild_finish(ib);

	struct sfdo_desktop_exec_scanner *exec_scanner = &loader.exec;

	free(exec_scanner->buf);
	free(exec_scanner->lit_buf);

	if (ok) {
		return db;
	} else {
		sfdo_desktop_db_destroy(db);
		return NULL;
	}
}

SFDO_API void sfdo_desktop_db_destroy(struct sfdo_desktop_db *db) {
	if (db == NULL) {
		return;
	}

	for (size_t i = 0; i < db->n_entries; i++) {
		desktop_entry_destroy(db->entries_list[i]);
	}
	free(db->entries_list);

	sfdo_hashmap_finish(&db->entries);
	sfdo_strpool_finish(&db->strings);

	free(db->basedirs_mem);
	free(db->basedirs);
	free(db);
}

SFDO_API struct sfdo_desktop_entry *sfdo_desktop_db_get_entry_by_id(
		struct sfdo_desktop_db *db, const char *id, size_t id_len) {
	if (id_len == SFDO_NT) {
		id_len = strlen(id);
	}
	struct sfdo_desktop_map_entry *map_entry = sfdo_hashmap_get(&db->entries, id, id_len, false);
	if (map_entry == NULL) {
		return NULL;
	}
	return map_entry->entry;
}

SFDO_API struct sfdo_desktop_entry **sfdo_desktop_db_get_entries(
		struct sfdo_desktop_db *db, size_t *n_entries) {
	*n_entries = db->n_entries;
	return db->entries_list;
}
