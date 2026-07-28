#ifndef AC_H
#define AC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <windows.h>

#define AC_MAX_MODULES 2048u
#define AC_MAX_SNAPSHOT_RETRIES 8u

typedef enum AcSeverity {
    AC_SEVERITY_INFO,
    AC_SEVERITY_LOW,
    AC_SEVERITY_MEDIUM,
    AC_SEVERITY_HIGH
} AcSeverity;

typedef struct AcLogger {
    FILE *file;
    bool mirror_to_console;
    CRITICAL_SECTION lock;
    bool lock_initialized;
} AcLogger;

typedef struct AcModule {
    uintptr_t base;
    size_t size;
    wchar_t path[MAX_PATH];
} AcModule;

typedef struct AcModuleList {
    AcModule items[AC_MAX_MODULES];
    size_t count;
    bool truncated;
} AcModuleList;

typedef struct AcScanStats {
    size_t module_count;
    size_t outside_expected_roots;
    size_t executable_region_count;
    size_t suspicious_region_count;
    size_t query_failures;
} AcScanStats;

typedef struct AcOptions {
    const wchar_t *process_name;
    const wchar_t *log_path;
    DWORD interval_ms;
    bool once;
} AcOptions;

bool ac_logger_open(AcLogger *logger, const wchar_t *path, bool mirror_to_console);
void ac_logger_close(AcLogger *logger);
void ac_log_event(
    AcLogger *logger,
    AcSeverity severity,
    const char *event,
    DWORD pid,
    const char *details_json);
void ac_log_win32_error(
    AcLogger *logger,
    const char *event,
    DWORD pid,
    DWORD error_code);

bool ac_find_process_by_name(const wchar_t *name, DWORD *pid_out);
HANDLE ac_open_process_for_scan(DWORD pid);
bool ac_get_process_path(HANDLE process, wchar_t *path_out, size_t path_capacity);
bool ac_get_parent_directory(
    const wchar_t *path,
    wchar_t *directory_out,
    size_t directory_capacity);

bool ac_collect_modules(DWORD pid, AcModuleList *modules, DWORD *error_out);
bool ac_path_is_under(const wchar_t *path, const wchar_t *directory);
bool ac_address_range_in_module(
    const AcModuleList *modules,
    uintptr_t base,
    size_t size);
bool ac_scan_process(
    AcLogger *logger,
    HANDLE process,
    DWORD pid,
    const wchar_t *game_directory,
    const wchar_t *windows_directory,
    uint64_t scan_id,
    AcScanStats *stats_out);

bool ac_wide_to_utf8(
    const wchar_t *input,
    char *output,
    size_t output_capacity);
void ac_json_escape(
    const char *input,
    char *output,
    size_t output_capacity);
const char *ac_severity_name(AcSeverity severity);

#endif
