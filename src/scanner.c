#include "ac.h"

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <wchar.h>

static bool ac_is_executable_protection(DWORD protection)
{
    const DWORD base = protection & 0xffu;

    return base == PAGE_EXECUTE ||
           base == PAGE_EXECUTE_READ ||
           base == PAGE_EXECUTE_READWRITE ||
           base == PAGE_EXECUTE_WRITECOPY;
}

static bool ac_is_writable_executable(DWORD protection)
{
    const DWORD base = protection & 0xffu;

    return base == PAGE_EXECUTE_READWRITE ||
           base == PAGE_EXECUTE_WRITECOPY;
}

static const char *ac_memory_type_name(DWORD type)
{
    switch (type) {
        case MEM_IMAGE: return "image";
        case MEM_MAPPED: return "mapped";
        case MEM_PRIVATE: return "private";
        default: return "unknown";
    }
}

static bool ac_ranges_overlap_or_contain(
    uintptr_t outer_base,
    size_t outer_size,
    uintptr_t inner_base,
    size_t inner_size)
{
    uintptr_t outer_end;
    uintptr_t inner_end;

    if (outer_size == 0 || inner_size == 0 ||
        outer_base > UINTPTR_MAX - outer_size ||
        inner_base > UINTPTR_MAX - inner_size) {
        return false;
    }

    outer_end = outer_base + outer_size;
    inner_end = inner_base + inner_size;
    return inner_base >= outer_base && inner_end <= outer_end;
}

bool ac_collect_modules(DWORD pid, AcModuleList *modules, DWORD *error_out)
{
    HANDLE snapshot = INVALID_HANDLE_VALUE;
    MODULEENTRY32W entry;
    DWORD error = ERROR_SUCCESS;
    unsigned int attempt;

    if (modules == NULL) {
        if (error_out != NULL) {
            *error_out = ERROR_INVALID_PARAMETER;
        }
        return false;
    }

    memset(modules, 0, sizeof(*modules));

    for (attempt = 0; attempt < AC_MAX_SNAPSHOT_RETRIES; ++attempt) {
        snapshot = CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
            pid);
        if (snapshot != INVALID_HANDLE_VALUE) {
            break;
        }

        error = GetLastError();
        if (error != ERROR_BAD_LENGTH) {
            if (error_out != NULL) {
                *error_out = error;
            }
            return false;
        }
        SwitchToThread();
    }

    if (snapshot == INVALID_HANDLE_VALUE) {
        if (error_out != NULL) {
            *error_out = error;
        }
        return false;
    }

    memset(&entry, 0, sizeof(entry));
    entry.dwSize = sizeof(entry);
    if (!Module32FirstW(snapshot, &entry)) {
        error = GetLastError();
        CloseHandle(snapshot);
        if (error_out != NULL) {
            *error_out = error;
        }
        return false;
    }

    do {
        AcModule *module;
        if (modules->count >= AC_MAX_MODULES) {
            modules->truncated = true;
            break;
        }

        module = &modules->items[modules->count++];
        module->base = (uintptr_t)entry.modBaseAddr;
        module->size = (size_t)entry.modBaseSize;
        (void)wcsncpy_s(
            module->path,
            sizeof(module->path) / sizeof(module->path[0]),
            entry.szExePath,
            _TRUNCATE);
    } while (Module32NextW(snapshot, &entry));

    error = GetLastError();
    CloseHandle(snapshot);

    if (error != ERROR_NO_MORE_FILES && !modules->truncated) {
        if (error_out != NULL) {
            *error_out = error;
        }
        return false;
    }

    if (error_out != NULL) {
        *error_out = ERROR_SUCCESS;
    }
    return true;
}

bool ac_path_is_under(const wchar_t *path, const wchar_t *directory)
{
    size_t directory_length;

    if (path == NULL || directory == NULL) {
        return false;
    }

    directory_length = wcslen(directory);
    while (directory_length > 0 &&
           (directory[directory_length - 1] == L'\\' ||
            directory[directory_length - 1] == L'/')) {
        --directory_length;
    }

    if (directory_length == 0 ||
        _wcsnicmp(path, directory, directory_length) != 0) {
        return false;
    }

    return path[directory_length] == L'\0' ||
           path[directory_length] == L'\\' ||
           path[directory_length] == L'/';
}

bool ac_address_range_in_module(
    const AcModuleList *modules,
    uintptr_t base,
    size_t size)
{
    size_t index;

    if (modules == NULL) {
        return false;
    }

    for (index = 0; index < modules->count; ++index) {
        const AcModule *module = &modules->items[index];
        if (ac_ranges_overlap_or_contain(
                module->base,
                module->size,
                base,
                size)) {
            return true;
        }
    }
    return false;
}

static void ac_log_module_signal(
    AcLogger *logger,
    DWORD pid,
    uint64_t scan_id,
    const AcModule *module)
{
    char path_utf8[MAX_PATH * 3];
    char escaped_path[MAX_PATH * 6];
    char details[2048];

    if (!ac_wide_to_utf8(module->path, path_utf8, sizeof(path_utf8))) {
        (void)strcpy_s(path_utf8, sizeof(path_utf8), "<path-conversion-failed>");
    }
    ac_json_escape(path_utf8, escaped_path, sizeof(escaped_path));
    (void)snprintf(
        details,
        sizeof(details),
        "{\"scan_id\":%" PRIu64 ",\"path\":\"%s\","
        "\"base\":\"0x%" PRIxPTR "\",\"size\":%zu,"
        "\"reason\":\"outside_expected_roots\","
        "\"verdict\":\"signal_only\"}",
        scan_id,
        escaped_path,
        module->base,
        module->size);
    ac_log_event(
        logger,
        AC_SEVERITY_LOW,
        "module_outside_expected_roots",
        pid,
        details);
}

static bool ac_scan_memory_regions(
    AcLogger *logger,
    HANDLE process,
    DWORD pid,
    uint64_t scan_id,
    const AcModuleList *modules,
    AcScanStats *stats)
{
    SYSTEM_INFO system_info;
    uintptr_t address;
    uintptr_t maximum_address;

    GetNativeSystemInfo(&system_info);
    address = (uintptr_t)system_info.lpMinimumApplicationAddress;
    maximum_address = (uintptr_t)system_info.lpMaximumApplicationAddress;

    while (address < maximum_address) {
        MEMORY_BASIC_INFORMATION memory;
        SIZE_T query_size;
        uintptr_t next_address;

        memset(&memory, 0, sizeof(memory));
        query_size = VirtualQueryEx(
            process,
            (LPCVOID)address,
            &memory,
            sizeof(memory));
        if (query_size == 0) {
            const DWORD error = GetLastError();
            ++stats->query_failures;
            if (error == ERROR_INVALID_PARAMETER) {
                break;
            }
            next_address = address + system_info.dwPageSize;
            if (next_address <= address) {
                break;
            }
            address = next_address;
            continue;
        }

        if (memory.RegionSize > UINTPTR_MAX - (uintptr_t)memory.BaseAddress) {
            break;
        }
        next_address = (uintptr_t)memory.BaseAddress + memory.RegionSize;
        if (next_address <= address) {
            break;
        }

        if (memory.State == MEM_COMMIT &&
            (memory.Protect & (PAGE_GUARD | PAGE_NOACCESS)) == 0 &&
            ac_is_executable_protection(memory.Protect)) {
            bool outside_module;
            bool suspicious;

            ++stats->executable_region_count;
            outside_module = !ac_address_range_in_module(
                modules,
                (uintptr_t)memory.BaseAddress,
                memory.RegionSize);
            suspicious = outside_module &&
                         (memory.Type == MEM_PRIVATE ||
                          ac_is_writable_executable(memory.Protect));

            if (suspicious) {
                char details[1024];
                const AcSeverity severity =
                    ac_is_writable_executable(memory.Protect)
                        ? AC_SEVERITY_MEDIUM
                        : AC_SEVERITY_LOW;

                ++stats->suspicious_region_count;
                (void)snprintf(
                    details,
                    sizeof(details),
                    "{\"scan_id\":%" PRIu64 ",\"base\":\"0x%" PRIxPTR
                    "\",\"size\":%zu,\"protect\":%lu,\"type\":\"%s\","
                    "\"outside_known_module\":true,"
                    "\"reason\":\"executable_non_image_memory\","
                    "\"verdict\":\"signal_only\"}",
                    scan_id,
                    (uintptr_t)memory.BaseAddress,
                    (size_t)memory.RegionSize,
                    (unsigned long)memory.Protect,
                    ac_memory_type_name(memory.Type));
                ac_log_event(
                    logger,
                    severity,
                    "suspicious_executable_region",
                    pid,
                    details);
            }
        }

        address = next_address;
    }

    return true;
}

bool ac_scan_process(
    AcLogger *logger,
    HANDLE process,
    DWORD pid,
    const wchar_t *game_directory,
    const wchar_t *windows_directory,
    uint64_t scan_id,
    AcScanStats *stats_out)
{
    AcModuleList *modules;
    AcScanStats stats;
    DWORD error;
    size_t index;
    char details[1024];

    if (logger == NULL || process == NULL || stats_out == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return false;
    }

    memset(&stats, 0, sizeof(stats));
    modules = (AcModuleList *)calloc(1, sizeof(*modules));
    if (modules == NULL) {
        SetLastError(ERROR_OUTOFMEMORY);
        return false;
    }

    if (!ac_collect_modules(pid, modules, &error)) {
        free(modules);
        SetLastError(error);
        return false;
    }

    stats.module_count = modules->count;
    for (index = 0; index < modules->count; ++index) {
        const AcModule *module = &modules->items[index];
        const bool expected =
            ac_path_is_under(module->path, game_directory) ||
            ac_path_is_under(module->path, windows_directory);

        if (!expected) {
            ++stats.outside_expected_roots;
            ac_log_module_signal(logger, pid, scan_id, module);
        }
    }

    (void)ac_scan_memory_regions(
        logger,
        process,
        pid,
        scan_id,
        modules,
        &stats);

    (void)snprintf(
        details,
        sizeof(details),
        "{\"scan_id\":%" PRIu64 ",\"modules\":%zu,"
        "\"module_list_truncated\":%s,\"outside_expected_roots\":%zu,"
        "\"executable_regions\":%zu,\"suspicious_regions\":%zu,"
        "\"query_failures\":%zu}",
        scan_id,
        stats.module_count,
        modules->truncated ? "true" : "false",
        stats.outside_expected_roots,
        stats.executable_region_count,
        stats.suspicious_region_count,
        stats.query_failures);
    ac_log_event(logger, AC_SEVERITY_INFO, "scan_completed", pid, details);

    *stats_out = stats;
    free(modules);
    return true;
}
