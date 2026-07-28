#ifndef AC_TEXT_H
#define AC_TEXT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define AC_FNV1A64_OFFSET 0xcbf29ce484222325ull

bool ac_json_escape(const char *input, char *output, size_t output_capacity);

uint64_t ac_fnv1a64_continue(uint64_t hash, const void *data, size_t length);
uint64_t ac_fnv1a64(const void *data, size_t length);
uint64_t ac_fnv1a64_text(uint64_t hash, const char *text);
uint64_t ac_fnv1a64_text_ci(uint64_t hash, const char *text);

#endif
