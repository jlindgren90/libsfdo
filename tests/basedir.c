#include <sfdo-basedir.h>
#include <sfdo-common.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_HOME "/home/sfdo-test-user"

static void check_string(
		const char *name, const char *got, size_t got_len, const char *exp, size_t exp_len) {
	if (exp_len == SFDO_NT) {
		exp_len = strlen(exp);
	}
	if (got_len != exp_len || memcmp(got, exp, exp_len) != 0) {
		fprintf(stderr,
				"\"%s\" string mismatch\n"
				"Expected (length: %zu):\t%s\n"
				"Got      (length: %zu):\t%s\n",
				name, got_len, got, exp_len, exp);
		exit(1);
	}
}

static void check_dirs(
		const char *name, const struct sfdo_string *got, size_t got_len, size_t exp_len, ...) {
	va_list args;
	va_start(args, exp_len);

	struct sfdo_string *exp = calloc(exp_len, sizeof(*exp));
	for (size_t i = 0; i < exp_len; i++) {
		exp[i].data = va_arg(args, const char *);
		exp[i].len = va_arg(args, size_t);
		if (exp[i].len == SFDO_NT) {
			exp[i].len = strlen(exp[i].data);
		}
	}

	va_end(args);

	if (got_len != exp_len) {
		goto mismatch;
	}

	for (size_t i = 0; i < exp_len; i++) {
		if (got[i].len != exp[i].len || memcmp(got[i].data, exp[i].data, got[i].len) != 0) {
			goto mismatch;
		}
	}

	free(exp);
	return;

mismatch:
	fprintf(stderr, "\"%s\" directory list mismatch\n", name);
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

static void test_home_dirs(const char *home) {
	setenv("HOME", home, 1);

	struct sfdo_basedir_ctx *ctx = sfdo_basedir_ctx_create();

	const char *data;
	size_t len;

	data = sfdo_basedir_get_data_home(ctx, &len);
	check_string("data home", data, len, TEST_HOME "/.local/share/", SFDO_NT);

	data = sfdo_basedir_get_config_home(ctx, &len);
	check_string("config home", data, len, TEST_HOME "/.config/", SFDO_NT);

	data = sfdo_basedir_get_state_home(ctx, &len);
	check_string("state home", data, len, TEST_HOME "/.local/state/", SFDO_NT);

	data = sfdo_basedir_get_cache_home(ctx, &len);
	check_string("cache home", data, len, TEST_HOME "/.cache/", SFDO_NT);

	sfdo_basedir_ctx_destroy(ctx);
}

static void test_system_dirs(void) {
	struct sfdo_basedir_ctx *ctx = sfdo_basedir_ctx_create();

	const struct sfdo_string *dirs;
	size_t n_dirs;

	dirs = sfdo_basedir_get_data_system_dirs(ctx, &n_dirs);
	check_dirs("data dirs", dirs, n_dirs, 2, "/usr/local/share/", SFDO_NT, "/usr/share/", SFDO_NT);

	dirs = sfdo_basedir_get_config_system_dirs(ctx, &n_dirs);
	check_dirs("config dirs", dirs, n_dirs, 1, "/etc/xdg/", SFDO_NT);

	sfdo_basedir_ctx_destroy(ctx);
}

static void reset(void) {
	unsetenv("HOME");

	unsetenv("XDG_DATA_HOME");
	unsetenv("XDG_DATA_DIRS");
	unsetenv("XDG_CONFIG_HOME");
	unsetenv("XDG_CONFIG_DIRS");
	unsetenv("XDG_STATE_HOME");
	unsetenv("XDG_CACHE_HOME");
	unsetenv("XDG_RUNTIME_DIR");
}

int main(void) {
	reset();
	test_home_dirs(TEST_HOME);
	test_home_dirs(TEST_HOME "/");

	reset();
	setenv("XDG_DATA_HOME", TEST_HOME "/.local/share", 1);
	setenv("XDG_CONFIG_HOME", TEST_HOME "/.config", 1);
	setenv("XDG_STATE_HOME", TEST_HOME "/.local/state", 1);
	setenv("XDG_CACHE_HOME", TEST_HOME "/.cache", 1);
	test_home_dirs("/UNUSED");

	reset();
	setenv("XDG_DATA_HOME", TEST_HOME "/.local/share/", 1);
	setenv("XDG_CONFIG_HOME", TEST_HOME "/.config/", 1);
	setenv("XDG_STATE_HOME", TEST_HOME "/.local/state/", 1);
	setenv("XDG_CACHE_HOME", TEST_HOME "/.cache/", 1);
	test_home_dirs("/UNUSED");

	reset();
	setenv("XDG_DATA_HOME", "../", 1);
	setenv("XDG_CONFIG_HOME", "../", 1);
	setenv("XDG_STATE_HOME", "../", 1);
	setenv("XDG_CACHE_HOME", "../", 1);
	test_home_dirs(TEST_HOME);

	reset();
	test_system_dirs();

	reset();
	setenv("XDG_DATA_DIRS", "/usr/local/share:/usr/share", 1);
	setenv("XDG_CONFIG_DIRS", "/etc/xdg", 1);
	test_system_dirs();

	reset();
	setenv("XDG_DATA_DIRS", "/usr/local/share/:../:::/usr/share/", 1);
	setenv("XDG_CONFIG_DIRS", "/etc/xdg/:", 1);
	test_system_dirs();

	return 0;
}
