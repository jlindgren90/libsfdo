#ifndef SFDO_BASEDIR_H
#define SFDO_BASEDIR_H

#include <sfdo-common.h>
#include <stdbool.h>

// libsfdo-basedir implements the XDG base directory specification:
//
//   https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html
//
// For convenience, all paths end with a slash.

struct sfdo_basedir_ctx;

// Create a context.
//
// Returns NULL on memory allocation error.
struct sfdo_basedir_ctx *sfdo_basedir_ctx_create(void);

// Destroy a context.
//
// ctx may be NULL, in which case the function is no-op.
void sfdo_basedir_ctx_destroy(struct sfdo_basedir_ctx *ctx);

// Get the preference-ordered set of base directories to search for data files including the
// user-specific directory.
//
// The number of directories is saved to n_directories.
const struct sfdo_string *sfdo_basedir_get_data_dirs(
		struct sfdo_basedir_ctx *ctx, size_t *n_directories);

// Get the base directory relative to which user-specific data files should be stored.
//
// The length of the path is saved to len. len may be NULL.
const char *sfdo_basedir_get_data_home(struct sfdo_basedir_ctx *ctx, size_t *len);

// Get the preference-ordered set of base directories to search for data files excluding the
// user-specific directory.
//
// The number of directories is saved to n_directories.
const struct sfdo_string *sfdo_basedir_get_data_system_dirs(
		struct sfdo_basedir_ctx *ctx, size_t *n_directories);

// Get the preference-ordered set of base directories to search for configuration files including
// the user-specific directory.
//
// The number of directories is saved to n_directories.
const struct sfdo_string *sfdo_basedir_get_config_dirs(
		struct sfdo_basedir_ctx *ctx, size_t *n_directories);

// Get the base directory relative to which user-specific configuration files should be stored.
//
// The length of the path is saved to len. len may be NULL.
const char *sfdo_basedir_get_config_home(struct sfdo_basedir_ctx *ctx, size_t *len);

// Get the preference-ordered set of base directories to search for configuration files excluding
// the user-specific directory.
//
// The number of directories is saved to n_directories.
const struct sfdo_string *sfdo_basedir_get_config_system_dirs(
		struct sfdo_basedir_ctx *ctx, size_t *n_directories);

// Get the base directory relative to which user-specific state files should be stored.
//
// The length of the path is saved to len. len may be NULL.
const char *sfdo_basedir_get_state_home(struct sfdo_basedir_ctx *ctx, size_t *len);

// Get the base directory relative to which user-specific non-essential data files should be stored.
//
// The length of the path is saved to len. len may be NULL.
const char *sfdo_basedir_get_cache_home(struct sfdo_basedir_ctx *ctx, size_t *len);

// Get the base directory relative to which user-specific non-essential runtime files and other file
// objects (such as sockets, named pipes, ...) should be stored.
//
// The length of the path is saved to len. len may be NULL.
//
// Returns NULL if the corresponding environment variable is unset or invalid.
const char *sfdo_basedir_get_runtime_dir(struct sfdo_basedir_ctx *ctx, size_t *len);

#endif
