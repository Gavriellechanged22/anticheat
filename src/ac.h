#ifndef AC_H
#define AC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <windows.h>

#include "dedup.h"
#include "ranges.h"
#include "sha256.h"
#include "text.h"

#define AC_AGENT_NAME "user-mode-anticheat"
#define AC_AGENT_VERSION "0.2.0"
#define AC_SCHEMA_VERSION 2u

#define AC_MAX_MODULES 8192u
#define AC_MAX_SNAPSHOT_RETRIES 16u
#define AC_MAX_ALLOW_ROOTS 24u
#define AC_PROBE_BYTES 4096u
#define AC_DEDUP_CAPACITY 4096u

typedef enum AcSeverity {
    AC_SEVERITY_INFO,
    AC_SEVERITY_LOW,
    AC_SEVERITY_MEDIUM,
    AC_SEVERITY_HIGH
} AcSeverity;

typedef struct AcLogger {
    FILE *file;
    wchar_t *path;
    bool mirror_to_console;
    bool rotating;
    CRITICAL_SECTION lock;
    bool lock_initialized;
    uint64_t sequence;
    uint64_t bytes_written;
    uint64_t max_bytes;
    unsigned int generations;
    uint64_t truncated_lines;
    uint64_t write_failures;
    uint8_t chain[AC_SHA256_DIGEST_SIZE];
} AcLogger;

typedef struct AcModule {
    uintptr_t base;
    size_t size;
    wchar_t path[MAX_PATH];
} AcModule;

typedef struct AcModuleList {
    AcModule *items;
    size_t count;
    size_t capacity;
    bool truncated;
} AcModuleList;

typedef struct AcPolicy {
    const wchar_t *allow_roots[AC_MAX_ALLOW_ROOTS];
    size_t allow_root_count;
    uint64_t probe_budget_bytes;
    uint64_t scan_budget_ms;
    uint64_t repeat_interval_ms;
    size_t max_regions;
    bool hash_unknown_modules;
    bool probe_region_content;
} AcPolicy;

typedef struct AcScanStats {
    size_t module_count;
    size_t modules_outside_roots;
    size_t regions_visited;
    size_t executable_region_count;
    size_t suspicious_region_count;
    size_t query_failures;
    size_t read_failures;
    uint64_t probe_bytes;
    uint64_t duration_ms;
    uint64_t emitted;
    uint64_t suppressed;
} AcScanStats;

typedef struct AcContext {
    AcLogger *logger;
    AcPolicy policy;
    AcModuleList modules;
    AcRangeIndex module_ranges;
    AcDedup dedup;
    uint8_t probe_buffer[AC_PROBE_BYTES];
    uint64_t scans_completed;
    uint64_t perf_budget_breaches;
} AcContext;

typedef struct AcTarget {
    HANDLE process;
    DWORD pid;
    DWORD granted_access;
    uint64_t start_time;
    wchar_t *image_path;
    wchar_t *directory;
} AcTarget;

bool ac_logger_open(
    AcLogger *logger,
    const wchar_t *path,
    bool mirror_to_console,
    uint64_t max_bytes,
    unsigned int generations);
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

bool ac_find_process_by_name(
    const wchar_t *name,
    DWORD *pid_out,
    size_t *match_count_out);
HANDLE ac_open_process_for_scan(DWORD pid, DWORD *granted_access_out);
bool ac_get_process_path(HANDLE process, wchar_t **path_out);
bool ac_get_process_start_time(HANDLE process, uint64_t *start_time_out);
bool ac_get_parent_directory(const wchar_t *path, wchar_t **directory_out);
bool ac_process_image_matches_name(const wchar_t *image_path, const wchar_t *name);

void ac_module_list_init(AcModuleList *modules);
void ac_module_list_free(AcModuleList *modules);
bool ac_module_list_push(
    AcModuleList *modules,
    uintptr_t base,
    size_t size,
    const wchar_t *path);
bool ac_collect_modules(DWORD pid, AcModuleList *modules, DWORD *error_out);
bool ac_path_is_under(const wchar_t *path, const wchar_t *directory);
bool ac_path_is_under_any(
    const wchar_t *path,
    const wchar_t **directories,
    size_t directory_count);

void ac_policy_init_defaults(AcPolicy *policy);
bool ac_context_init(AcContext *context, AcLogger *logger, const AcPolicy *policy);
void ac_context_free(AcContext *context);
bool ac_scan_process(
    AcContext *context,
    const AcTarget *target,
    uint64_t scan_id,
    AcScanStats *stats_out);

bool ac_hash_file(const wchar_t *path, char hex_out[AC_SHA256_HEX_SIZE], uint64_t *size_out);
bool ac_wide_to_utf8(const wchar_t *input, char *output, size_t output_capacity);
bool ac_wide_to_utf8_alloc(const wchar_t *input, char **output);
const char *ac_severity_name(AcSeverity severity);

#endif
