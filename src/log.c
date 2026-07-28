#include "ac.h"

#include <limits.h>
#include <string.h>

void ac_json_escape(
    const char *input,
    char *output,
    size_t output_capacity)
{
    size_t in_index = 0;
    size_t out_index = 0;

    if (output == NULL || output_capacity == 0) {
        return;
    }
    output[0] = '\0';
    if (input == NULL) {
        return;
    }

    while (input[in_index] != '\0' && out_index + 1 < output_capacity) {
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
                break;
            }
            memcpy(output + out_index, escape, escape_length);
            out_index += escape_length;
        } else if (ch < 0x20u) {
            if (out_index + 6 >= output_capacity) {
                break;
            }
            (void)snprintf(
                output + out_index,
                output_capacity - out_index,
                "\\u%04x",
                (unsigned int)ch);
            out_index += 6;
        } else {
            output[out_index++] = (char)ch;
        }
    }

    output[out_index] = '\0';
}

static bool ac_write_line(AcLogger *logger, const char *line)
{
    bool ok = true;

    if (logger == NULL || !logger->lock_initialized) {
        return false;
    }

    EnterCriticalSection(&logger->lock);

    if (logger->file != NULL) {
        if (fputs(line, logger->file) == EOF ||
            fputc('\n', logger->file) == EOF ||
            fflush(logger->file) != 0) {
            ok = false;
        }
    }

    if (logger->mirror_to_console) {
        (void)fputs(line, stdout);
        (void)fputc('\n', stdout);
        (void)fflush(stdout);
    }

    LeaveCriticalSection(&logger->lock);
    return ok;
}

bool ac_logger_open(AcLogger *logger, const wchar_t *path, bool mirror_to_console)
{
    if (logger == NULL || path == NULL) {
        return false;
    }

    memset(logger, 0, sizeof(*logger));
    InitializeCriticalSection(&logger->lock);
    logger->lock_initialized = true;
    logger->mirror_to_console = mirror_to_console;
    logger->file = _wfopen(path, L"ab");

    if (logger->file == NULL) {
        ac_logger_close(logger);
        return false;
    }

    return true;
}

void ac_logger_close(AcLogger *logger)
{
    if (logger == NULL) {
        return;
    }

    if (logger->file != NULL) {
        (void)fclose(logger->file);
        logger->file = NULL;
    }

    if (logger->lock_initialized) {
        DeleteCriticalSection(&logger->lock);
        logger->lock_initialized = false;
    }
}

const char *ac_severity_name(AcSeverity severity)
{
    switch (severity) {
        case AC_SEVERITY_INFO: return "info";
        case AC_SEVERITY_LOW: return "low";
        case AC_SEVERITY_MEDIUM: return "medium";
        case AC_SEVERITY_HIGH: return "high";
        default: return "unknown";
    }
}

void ac_log_event(
    AcLogger *logger,
    AcSeverity severity,
    const char *event,
    DWORD pid,
    const char *details_json)
{
    SYSTEMTIME timestamp;
    char escaped_event[256];
    char line[8192];
    const char *details = details_json != NULL ? details_json : "{}";

    GetSystemTime(&timestamp);
    ac_json_escape(event != NULL ? event : "unknown", escaped_event, sizeof(escaped_event));

    (void)snprintf(
        line,
        sizeof(line),
        "{\"timestamp\":\"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ\","
        "\"severity\":\"%s\",\"event\":\"%s\",\"pid\":%lu,\"details\":%s}",
        (unsigned int)timestamp.wYear,
        (unsigned int)timestamp.wMonth,
        (unsigned int)timestamp.wDay,
        (unsigned int)timestamp.wHour,
        (unsigned int)timestamp.wMinute,
        (unsigned int)timestamp.wSecond,
        (unsigned int)timestamp.wMilliseconds,
        ac_severity_name(severity),
        escaped_event,
        (unsigned long)pid,
        details);

    (void)ac_write_line(logger, line);
}

void ac_log_win32_error(
    AcLogger *logger,
    const char *event,
    DWORD pid,
    DWORD error_code)
{
    wchar_t wide_message[512];
    char utf8_message[1536];
    char escaped_message[3072];
    char details[4096];
    DWORD length;

    wide_message[0] = L'\0';
    length = FormatMessageW(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        error_code,
        0,
        wide_message,
        (DWORD)(sizeof(wide_message) / sizeof(wide_message[0])),
        NULL);

    while (length > 0 &&
           (wide_message[length - 1] == L'\r' ||
            wide_message[length - 1] == L'\n' ||
            wide_message[length - 1] == L' ')) {
        wide_message[--length] = L'\0';
    }

    if (!ac_wide_to_utf8(
            length > 0 ? wide_message : L"Unknown Win32 error",
            utf8_message,
            sizeof(utf8_message))) {
        (void)strcpy_s(utf8_message, sizeof(utf8_message), "Unknown Win32 error");
    }

    ac_json_escape(utf8_message, escaped_message, sizeof(escaped_message));
    (void)snprintf(
        details,
        sizeof(details),
        "{\"win32_error\":%lu,\"message\":\"%s\"}",
        (unsigned long)error_code,
        escaped_message);
    ac_log_event(logger, AC_SEVERITY_LOW, event, pid, details);
}

bool ac_wide_to_utf8(
    const wchar_t *input,
    char *output,
    size_t output_capacity)
{
    int result;

    if (input == NULL || output == NULL || output_capacity == 0 ||
        output_capacity > INT_MAX) {
        return false;
    }

    result = WideCharToMultiByte(
        CP_UTF8,
        WC_ERR_INVALID_CHARS,
        input,
        -1,
        output,
        (int)output_capacity,
        NULL,
        NULL);
    return result > 0;
}
