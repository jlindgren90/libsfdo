#include <sfdo-common.h>
#include <sfdo-desktop-file.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

static struct sfdo_desktop_file_document *load_doc(const char *str, size_t len, const char *locale,
		int options, struct sfdo_desktop_file_error *error) {
	if (len == SFDO_NT) {
		len = strlen(str);
	}
	FILE *fp = fmemopen((char *)str, len, "r");
	struct sfdo_desktop_file_document *doc =
			sfdo_desktop_file_document_load(fp, locale, options, error);
	fclose(fp);
	return doc;
}

static void load_error(const char *name, const char *str, size_t len, const char *locale,
		int options, enum sfdo_desktop_file_error_code exp_code, int exp_line, int exp_column) {
	struct sfdo_desktop_file_error got;
	struct sfdo_desktop_file_document *doc = load_doc(str, len, locale, options, &got);
	if (doc != NULL) {
		fprintf(stderr,
				"\"%s\" unexpected success\n"
				"Expected: %d:%d: %s\n",
				name, exp_line, exp_column, sfdo_desktop_file_error_code_get_description(exp_code));
		exit(1);
	}
	if (exp_line != got.line || exp_column != got.column || exp_code != got.code) {
		fprintf(stderr,
				"\"%s\" error mismatch\n"
				"Expected: %d:%d:\t%s\n"
				"Got:      %d:%d:\t%s\n",
				name, exp_line, exp_column, sfdo_desktop_file_error_code_get_description(exp_code),
				got.line, got.column, sfdo_desktop_file_error_code_get_description(got.code));
		exit(1);
	}
}

static struct sfdo_desktop_file_document *load_success(
		const char *name, const char *str, size_t len, const char *locale, int options) {
	struct sfdo_desktop_file_error error;
	struct sfdo_desktop_file_document *doc = load_doc(str, len, locale, options, &error);
	if (doc == NULL) {
		fprintf(stderr, "\"%s\" unexpected error: %d:%d: %s\n", name, error.line, error.column,
				sfdo_desktop_file_error_code_get_description(error.code));
		exit(1);
	}

	return doc;
}

static void check_value(const char *name, const char *str, size_t len, const char *locale,
		int options, bool localized, const char *exp) {
	struct sfdo_desktop_file_document *doc = load_success(name, str, len, locale, options);

	struct sfdo_desktop_file_group *group = sfdo_desktop_file_document_get_groups(doc);
	if (group == NULL) {
		fprintf(stderr, "\"%s\" has no groups?", name);
		exit(1);
	}

	struct sfdo_desktop_file_entry *entry = sfdo_desktop_file_group_get_entry(group, "key", 3);
	if (group == NULL) {
		fprintf(stderr, "\"%s\" has no \"key\" entry?", name);
		exit(1);
	}

	size_t exp_len = strlen(exp);

	size_t got_len;
	const char *got = localized ? sfdo_desktop_file_entry_get_localized_value(entry, &got_len)
								: sfdo_desktop_file_entry_get_value(entry, &got_len);
	if (got_len != exp_len || memcmp(got, exp, exp_len) != 0) {
		fprintf(stderr,
				"\"%s\" value mismatch\n"
				"Expected (length: %zu):\t%s\n"
				"Got      (length: %zu):\t%s\n",
				name, got_len, got, exp_len, exp);
		exit(1);
	}

	sfdo_desktop_file_document_destroy(doc);
}

static void check_value_list(const char *name, const char *str, size_t len, const char *locale,
		int options, bool localized, size_t exp_len, ...) {
	struct sfdo_desktop_file_document *doc = load_success(name, str, len, locale, options);

	struct sfdo_desktop_file_group *group = sfdo_desktop_file_document_get_groups(doc);
	if (group == NULL) {
		fprintf(stderr, "\"%s\" has no groups?", name);
		exit(1);
	}

	struct sfdo_desktop_file_entry *entry = sfdo_desktop_file_group_get_entry(group, "key", 3);
	if (group == NULL) {
		fprintf(stderr, "\"%s\" has no \"key\" entry?", name);
		exit(1);
	}

	va_list args;
	va_start(args, exp_len);

	struct sfdo_string *exp = calloc(exp_len, sizeof(*exp));
	for (size_t i = 0; i < exp_len; i++) {
		exp[i].data = va_arg(args, const char *);
		exp[i].len = strlen(exp[i].data);
	}

	va_end(args);

	size_t got_len;
	const struct sfdo_string *got = localized
			? sfdo_desktop_file_entry_get_localized_value_list(entry, &got_len)
			: sfdo_desktop_file_entry_get_value_list(entry, &got_len);

	if (got_len != exp_len) {
		goto mismatch;
	}

	for (size_t i = 0; i < exp_len; i++) {
		if (got[i].len != exp[i].len || memcmp(got[i].data, exp[i].data, got[i].len) != 0) {
			goto mismatch;
		}
	}

	free(exp);
	sfdo_desktop_file_document_destroy(doc);
	return;

mismatch:
	fprintf(stderr, "\"%s\" value list mismatch\n", name);
	fprintf(stderr, "Expected (length: %zu):\n", exp_len);
	for (size_t i = 0; i < exp_len; i++) {
		fprintf(stderr, "  %zu)\t(length: %zu)\t%s\n", i, exp[i].len, exp[i].data);
	}
	fprintf(stderr, "Got (length: %zu):\n", got_len);
	for (size_t i = 0; i < got_len; i++) {
		fprintf(stderr, "  %zu)\t(length: %zu)\t%s\n", i, got[i].len, got[i].data);
	}

	exit(1);
}

int main(void) {
	// Basic parsing

	load_error("NUL", "[Group\0Name]\n", 15, NULL, SFDO_DESKTOP_FILE_LOAD_OPTIONS_DEFAULT,
			SFDO_DESKTOP_FILE_ERROR_NT, 1, 7);

	load_error("invalid UTF-8", "[Group\xffName]\n", SFDO_NT, NULL,
			SFDO_DESKTOP_FILE_LOAD_OPTIONS_DEFAULT, SFDO_DESKTOP_FILE_ERROR_UTF8, 1, 7);

	load_error("bad group char", "[Group[]\n", SFDO_NT, NULL,
			SFDO_DESKTOP_FILE_LOAD_OPTIONS_DEFAULT, SFDO_DESKTOP_FILE_ERROR_SYNTAX, 1, 7);

	load_error("extra after group", "[Group] extra\n", SFDO_NT, NULL,
			SFDO_DESKTOP_FILE_LOAD_OPTIONS_DEFAULT, SFDO_DESKTOP_FILE_ERROR_SYNTAX, 1, 9);

	load_error("entry without a group", "key=value\n", SFDO_NT, NULL,
			SFDO_DESKTOP_FILE_LOAD_OPTIONS_DEFAULT, SFDO_DESKTOP_FILE_ERROR_SYNTAX, 1, 1);

	load_error("bad key char",
			"[Group]\n"
			"key_name=value\n",
			SFDO_NT, NULL, SFDO_DESKTOP_FILE_LOAD_OPTIONS_DEFAULT, SFDO_DESKTOP_FILE_ERROR_SYNTAX,
			2, 4);

	load_error("entry with no value",
			"[Group]\n"
			"key\n",
			SFDO_NT, NULL, SFDO_DESKTOP_FILE_LOAD_OPTIONS_DEFAULT, SFDO_DESKTOP_FILE_ERROR_SYNTAX,
			2, 4);

	// The error is on \n
	load_error("truncated localized entry",
			"[Group]\n"
			"key[locale\n",
			SFDO_NT, NULL, SFDO_DESKTOP_FILE_LOAD_OPTIONS_DEFAULT, SFDO_DESKTOP_FILE_ERROR_SYNTAX,
			2, 11);

	load_error("localized entry with no value",
			"[Group]\n"
			"key[locale]\n",
			SFDO_NT, NULL, SFDO_DESKTOP_FILE_LOAD_OPTIONS_DEFAULT, SFDO_DESKTOP_FILE_ERROR_SYNTAX,
			2, 12);

	load_error("bad escaped character",
			"[Group]\n"
			"key=value\\a\n",
			SFDO_NT, NULL, SFDO_DESKTOP_FILE_LOAD_OPTIONS_DEFAULT, SFDO_DESKTOP_FILE_ERROR_SYNTAX,
			2, 11);

	load_error("truncated escaped character",
			"[Group]\n"
			"key=value\\\n",
			SFDO_NT, NULL, SFDO_DESKTOP_FILE_LOAD_OPTIONS_DEFAULT, SFDO_DESKTOP_FILE_ERROR_SYNTAX,
			2, 11);

	load_error("duplicate groups",
			"[Group]\n"
			"[Group]\n",
			SFDO_NT, NULL, SFDO_DESKTOP_FILE_LOAD_OPTIONS_DEFAULT,
			SFDO_DESKTOP_FILE_ERROR_DUPLICATE_GROUP, 2, 1);

	load_error("duplicate keys",
			"[Group]\n"
			"key=value\n"
			"key=value\n",
			SFDO_NT, NULL, SFDO_DESKTOP_FILE_LOAD_OPTIONS_DEFAULT,
			SFDO_DESKTOP_FILE_ERROR_DUPLICATE_KEY, 3, 1);

	load_error("no default value",
			"[Group]\n"
			"key[en_US]=value\n",
			SFDO_NT, NULL, SFDO_DESKTOP_FILE_LOAD_OPTIONS_DEFAULT,
			SFDO_DESKTOP_FILE_ERROR_NO_DEFAULT_VALUE, 2, 1);

	check_value("simple value",
			"[Group]\n"
			"key=value\n",
			SFDO_NT, NULL, SFDO_DESKTOP_FILE_LOAD_OPTIONS_DEFAULT, false, "value");

	// NB: trailing spaces are not ignored, same as GLib
	check_value("simple value with spaces",
			"  [Group]  \n"
			"   key    =    value\n",
			SFDO_NT, NULL, SFDO_DESKTOP_FILE_LOAD_OPTIONS_DEFAULT, false, "value");

	check_value("simple value a comment",
			"[Group]\n"
			"# comment\n"
			"key=value\n",
			SFDO_NT, NULL, SFDO_DESKTOP_FILE_LOAD_OPTIONS_DEFAULT, false, "value");

	check_value("simple value with localized getter",
			"[Group]\n"
			"key=value\n",
			SFDO_NT, NULL, SFDO_DESKTOP_FILE_LOAD_OPTIONS_DEFAULT, true, "value");

	check_value("escaped",
			"[Group]\n"
			"key=\\s\\n\\t\\r\\\\\n",
			SFDO_NT, NULL, SFDO_DESKTOP_FILE_LOAD_OPTIONS_DEFAULT, false, " \n\t\r\\");

	// Localized values

	static const char localized_str[] =
			"[Group]\n"
			"key=default\n"
			"\n"
			"key[lang]=lang\n"
			"key[lang@MODIFIER]=lang@MODIFIER\n"
			"key[lang_COUNTRY]=lang_COUNTRY\n"
			"key[lang_COUNTRY@MODIFIER]=lang_COUNTRY@MODIFIER\n"
			"\n"
			"key[lang2@MODIFIER]=lang2@MODIFIER\n"
			"key[lang2_COUNTRY]=lang2_COUNTRY\n";

	check_value("localized, no locale", localized_str, sizeof(localized_str) - 1, NULL,
			SFDO_DESKTOP_FILE_LOAD_OPTIONS_DEFAULT, true, "default");

	check_value("localized, empty locale", localized_str, sizeof(localized_str) - 1, "",
			SFDO_DESKTOP_FILE_LOAD_OPTIONS_DEFAULT, true, "default");

	check_value("localized, lang", localized_str, sizeof(localized_str) - 1, "lang",
			SFDO_DESKTOP_FILE_LOAD_OPTIONS_DEFAULT, true, "lang");

	check_value("localized, lang+modifier", localized_str, sizeof(localized_str) - 1,
			"lang@MODIFIER", SFDO_DESKTOP_FILE_LOAD_OPTIONS_DEFAULT, true, "lang@MODIFIER");

	check_value("localized, lang+country", localized_str, sizeof(localized_str) - 1, "lang_COUNTRY",
			SFDO_DESKTOP_FILE_LOAD_OPTIONS_DEFAULT, true, "lang_COUNTRY");

	check_value("localized, lang+country+modifier", localized_str, sizeof(localized_str) - 1,
			"lang_COUNTRY@MODIFIER", SFDO_DESKTOP_FILE_LOAD_OPTIONS_DEFAULT, true,
			"lang_COUNTRY@MODIFIER");

	check_value("localized, lang+country+modifier with encoding", localized_str,
			sizeof(localized_str) - 1, "lang_COUNTRY.ENCODING@MODIFIER",
			SFDO_DESKTOP_FILE_LOAD_OPTIONS_DEFAULT, true, "lang_COUNTRY@MODIFIER");

	check_value("localized, (bad)lang", localized_str, sizeof(localized_str) - 1, "BAD",
			SFDO_DESKTOP_FILE_LOAD_OPTIONS_DEFAULT, true, "default");

	check_value("localized, lang+(bad)modifier", localized_str, sizeof(localized_str) - 1,
			"lang@BAD", SFDO_DESKTOP_FILE_LOAD_OPTIONS_DEFAULT, true, "lang");

	check_value("localized, lang+(bad)country", localized_str, sizeof(localized_str) - 1,
			"lang_BAD", SFDO_DESKTOP_FILE_LOAD_OPTIONS_DEFAULT, true, "lang");

	check_value("localized, lang+country+(bad)modifier", localized_str, sizeof(localized_str) - 1,
			"lang_COUNTRY@BAD", SFDO_DESKTOP_FILE_LOAD_OPTIONS_DEFAULT, true, "lang_COUNTRY");

	check_value("localized, lang+(bad)country+modifier", localized_str, sizeof(localized_str) - 1,
			"lang_BAD@MODIFIER", SFDO_DESKTOP_FILE_LOAD_OPTIONS_DEFAULT, true, "lang@MODIFIER");

	check_value("localized, lang+(bad)country+(bad)modifier", localized_str,
			sizeof(localized_str) - 1, "lang_BAD@BAD", SFDO_DESKTOP_FILE_LOAD_OPTIONS_DEFAULT, true,
			"lang");

	check_value("localized, lang2", localized_str, sizeof(localized_str) - 1, "default",
			SFDO_DESKTOP_FILE_LOAD_OPTIONS_DEFAULT, true, "default");

	check_value("localized, lang2+country", localized_str, sizeof(localized_str) - 1,
			"lang2_COUNTRY", SFDO_DESKTOP_FILE_LOAD_OPTIONS_DEFAULT, true, "lang2_COUNTRY");

	check_value("localized, lang2+modifier", localized_str, sizeof(localized_str) - 1,
			"lang2@MODIFIER", SFDO_DESKTOP_FILE_LOAD_OPTIONS_DEFAULT, true, "lang2@MODIFIER");

	check_value("localized, lang2+country+modifier", localized_str, sizeof(localized_str) - 1,
			"lang2_COUNTRY@MODIFIER", SFDO_DESKTOP_FILE_LOAD_OPTIONS_DEFAULT, true,
			"lang2_COUNTRY");

	// Lists

	check_value_list("list with one item",
			"[Group]\n"
			"key = single",
			SFDO_NT, NULL, SFDO_DESKTOP_FILE_LOAD_OPTIONS_DEFAULT, false, 1, "single");

	check_value_list("list with zero items",
			"[Group]\n"
			"key = ",
			SFDO_NT, NULL, SFDO_DESKTOP_FILE_LOAD_OPTIONS_DEFAULT, false, 0);

	check_value_list("list with two items",
			"[Group]\n"
			"key = alpha;beta",
			SFDO_NT, NULL, SFDO_DESKTOP_FILE_LOAD_OPTIONS_DEFAULT, false, 2, "alpha", "beta");

	check_value_list("list with two items + trailing separator",
			"[Group]\n"
			"key = alpha;beta;",
			SFDO_NT, NULL, SFDO_DESKTOP_FILE_LOAD_OPTIONS_DEFAULT, false, 2, "alpha", "beta");

	check_value_list("list with two items, the first is empty",
			"[Group]\n"
			"key = ;beta",
			SFDO_NT, NULL, SFDO_DESKTOP_FILE_LOAD_OPTIONS_DEFAULT, false, 2, "", "beta");

	check_value_list("list with two items, the second is empty",
			"[Group]\n"
			"key = alpha;;",
			SFDO_NT, NULL, SFDO_DESKTOP_FILE_LOAD_OPTIONS_DEFAULT, false, 2, "alpha", "");

	check_value_list("list with one empty item",
			"[Group]\n"
			"key = ;",
			SFDO_NT, NULL, SFDO_DESKTOP_FILE_LOAD_OPTIONS_DEFAULT, false, 1, "");

	check_value_list("list with three items, the second is empty",
			"[Group]\n"
			"key = foo;;bar",
			SFDO_NT, NULL, SFDO_DESKTOP_FILE_LOAD_OPTIONS_DEFAULT, false, 3, "foo", "", "bar");

	check_value_list("list with items with escaped separators",
			"[Group]\n"
			"key = Steins\\;Gate;Chaos\\;Head;",
			SFDO_NT, NULL, SFDO_DESKTOP_FILE_LOAD_OPTIONS_DEFAULT, false, 2, "Steins;Gate",
			"Chaos;Head");

	return 0;
}
