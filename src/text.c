#include "text.h"

#include <stdio.h>
#include <string.h>

bool ac_json_escape(const char *input, char *output, size_t output_capacity)
{
    size_t in_index = 0;
    size_t out_index = 0;
    bool complete = true;

    if (output == NULL || output_capacity == 0) {
        return false;
    }
    output[0] = '\0';
    if (input == NULL) {
        return true;
    }

    while (input[in_index] != '\0') {
        const unsigned char ch = (unsigned char)input[in_index++];
        const char *escape = NULL;

        switch (ch) {
            case '"': escape = "\\\""; break;
            case '\\': escape = "\\\\"; break;
            case '\b': escape = "\\b"; break;
            case '\f': escape = "\\f"; break;
            case '\n': escape = "\\n"; break;
            case '\r': escape = "\\r"; break;
            case '\t': escape = "\\t"; break;
            default: break;
        }

        if (escape != NULL) {
            const size_t escape_length = strlen(escape);
            if (out_index + escape_length >= output_capacity) {
                complete = false;
                break;
            }
            memcpy(output + out_index, escape, escape_length);
            out_index += escape_length;
        } else if (ch < 0x20u || ch == 0x7fu) {
            if (out_index + 6u >= output_capacity) {
                complete = false;
                break;
            }
            (void)snprintf(
                output + out_index,
                output_capacity - out_index,
                "\\u%04x",
                (unsigned int)ch);
            out_index += 6u;
        } else {
            if (out_index + 1u >= output_capacity) {
                complete = false;
                break;
            }
            output[out_index++] = (char)ch;
        }
    }

    output[out_index] = '\0';
    return complete;
}

uint64_t ac_fnv1a64_continue(uint64_t hash, const void *data, size_t length)
{
    const unsigned char *bytes = (const unsigned char *)data;
    size_t index;

    if (bytes == NULL) {
        return hash;
    }

    for (index = 0; index < length; ++index) {
        hash ^= (uint64_t)bytes[index];
        hash *= 0x100000001b3ull;
    }
    return hash;
}

uint64_t ac_fnv1a64(const void *data, size_t length)
{
    return ac_fnv1a64_continue(AC_FNV1A64_OFFSET, data, length);
}

uint64_t ac_fnv1a64_text(uint64_t hash, const char *text)
{
    if (text == NULL) {
        return hash;
    }
    return ac_fnv1a64_continue(hash, text, strlen(text));
}

uint64_t ac_fnv1a64_text_ci(uint64_t hash, const char *text)
{
    size_t index;

    if (text == NULL) {
        return hash;
    }

    for (index = 0; text[index] != '\0'; ++index) {
        unsigned char ch = (unsigned char)text[index];
        if (ch >= 'A' && ch <= 'Z') {
            ch = (unsigned char)(ch - 'A' + 'a');
        }
        hash ^= (uint64_t)ch;
        hash *= 0x100000001b3ull;
    }
    return hash;
}
