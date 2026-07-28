#include "ac.h"

#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <wchar.h>

bool ac_find_process_by_name(
    const wchar_t *name,
    DWORD *pid_out,
    size_t *match_count_out)
{
    HANDLE snapshot;
    PROCESSENTRY32W entry;
    size_t matches = 0;
    DWORD first_match = 0;

    if (match_count_out != NULL) {
        *match_count_out = 0;
    }
    if (name == NULL || pid_out == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return false;
    }

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    memset(&entry, 0, sizeof(entry));
    entry.dwSize = sizeof(entry);
    if (!Process32FirstW(snapshot, &entry)) {
        const DWORD error = GetLastError();
        CloseHandle(snapshot);
        SetLastError(error);
        return false;
    }

    do {
        if (_wcsicmp(entry.szExeFile, name) == 0) {
            if (matches == 0) {
                first_match = entry.th32ProcessID;
            }
            ++matches;
        }
    } while (Process32NextW(snapshot, &entry));

    CloseHandle(snapshot);

    if (match_count_out != NULL) {
        *match_count_out = matches;
    }
    if (matches == 0) {
        SetLastError(ERROR_NOT_FOUND);
        return false;
    }

    *pid_out = first_match;
    return true;
}

static bool ac_process_supports_query(HANDLE process)
{
    MEMORY_BASIC_INFORMATION memory;

    memset(&memory, 0, sizeof(memory));
    if (VirtualQueryEx(process, NULL, &memory, sizeof(memory)) != 0) {
        return true;
    }
    return GetLastError() != ERROR_ACCESS_DENIED;
}

HANDLE ac_open_process_for_scan(DWORD pid, DWORD *granted_access_out)
{
    static const DWORD access_levels[] = {
        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ | SYNCHRONIZE,
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | SYNCHRONIZE
    };
    size_t index;
    DWORD last_error = ERROR_ACCESS_DENIED;

    if (granted_access_out != NULL) {
        *granted_access_out = 0;
    }

    for (index = 0; index < sizeof(access_levels) / sizeof(access_levels[0]); ++index) {
        HANDLE process = OpenProcess(access_levels[index], FALSE, pid);

        if (process == NULL) {
            last_error = GetLastError();
            continue;
        }

        if (!ac_process_supports_query(process)) {
            CloseHandle(process);
            last_error = ERROR_ACCESS_DENIED;
            continue;
        }

        if (granted_access_out != NULL) {
            *granted_access_out = access_levels[index];
        }
        return process;
    }

    SetLastError(last_error);
    return NULL;
}

bool ac_get_process_path(HANDLE process, wchar_t **path_out)
{
    DWORD capacity = MAX_PATH;

    if (process == NULL || path_out == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return false;
    }
    *path_out = NULL;

    while (capacity <= 32768u) {
        DWORD length = capacity;
        wchar_t *buffer = (wchar_t *)malloc((size_t)capacity * sizeof(wchar_t));

        if (buffer == NULL) {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            return false;
        }

        if (QueryFullProcessImageNameW(process, 0, buffer, &length)) {
            buffer[length < capacity ? length : capacity - 1u] = L'\0';
            *path_out = buffer;
            return true;
        }

        free(buffer);
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            return false;
        }
        capacity *= 2u;
    }

    SetLastError(ERROR_INSUFFICIENT_BUFFER);
    return false;
}

bool ac_get_process_start_time(HANDLE process, uint64_t *start_time_out)
{
    FILETIME creation;
    FILETIME exit_time;
    FILETIME kernel_time;
    FILETIME user_time;
    ULARGE_INTEGER value;

    if (process == NULL || start_time_out == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return false;
    }

    if (!GetProcessTimes(process, &creation, &exit_time, &kernel_time, &user_time)) {
        return false;
    }

    value.LowPart = creation.dwLowDateTime;
    value.HighPart = creation.dwHighDateTime;
    *start_time_out = (uint64_t)value.QuadPart;
    return true;
}

bool ac_get_parent_directory(const wchar_t *path, wchar_t **directory_out)
{
    wchar_t *buffer;
    wchar_t *separator;
    size_t length;

    if (path == NULL || directory_out == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return false;
    }
    *directory_out = NULL;

    length = wcslen(path);
    buffer = (wchar_t *)malloc((length + 1u) * sizeof(wchar_t));
    if (buffer == NULL) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return false;
    }
    (void)wcscpy_s(buffer, length + 1u, path);

    separator = wcsrchr(buffer, L'\\');
    if (separator == NULL) {
        separator = wcsrchr(buffer, L'/');
    }
    if (separator == NULL) {
        free(buffer);
        SetLastError(ERROR_BAD_PATHNAME);
        return false;
    }

    if (separator == buffer + 2u && buffer[1] == L':') {
        separator[1] = L'\0';
    } else {
        *separator = L'\0';
    }

    *directory_out = buffer;
    return true;
}

bool ac_process_image_matches_name(const wchar_t *image_path, const wchar_t *name)
{
    const wchar_t *base;
    const wchar_t *separator;

    if (image_path == NULL || name == NULL) {
        return false;
    }

    base = image_path;
    separator = wcsrchr(image_path, L'\\');
    if (separator != NULL) {
        base = separator + 1;
    }
    separator = wcsrchr(base, L'/');
    if (separator != NULL) {
        base = separator + 1;
    }

    return _wcsicmp(base, name) == 0;
}
