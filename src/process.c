#include "ac.h"

#include <tlhelp32.h>
#include <wchar.h>

bool ac_find_process_by_name(const wchar_t *name, DWORD *pid_out)
{
    HANDLE snapshot;
    PROCESSENTRY32W entry;
    bool found = false;

    if (name == NULL || pid_out == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return false;
    }

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    entry.dwSize = sizeof(entry);
    if (!Process32FirstW(snapshot, &entry)) {
        const DWORD error = GetLastError();
        CloseHandle(snapshot);
        SetLastError(error);
        return false;
    }

    do {
        if (_wcsicmp(entry.szExeFile, name) == 0) {
            *pid_out = entry.th32ProcessID;
            found = true;
            break;
        }
    } while (Process32NextW(snapshot, &entry));

    CloseHandle(snapshot);
    if (!found) {
        SetLastError(ERROR_NOT_FOUND);
    }
    return found;
}

HANDLE ac_open_process_for_scan(DWORD pid)
{
    return OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE,
        pid);
}

bool ac_get_process_path(HANDLE process, wchar_t *path_out, size_t path_capacity)
{
    DWORD capacity;

    if (process == NULL || path_out == NULL || path_capacity == 0 ||
        path_capacity > MAXDWORD) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return false;
    }

    capacity = (DWORD)path_capacity;
    if (!QueryFullProcessImageNameW(process, 0, path_out, &capacity)) {
        return false;
    }

    path_out[path_capacity - 1] = L'\0';
    return true;
}

bool ac_get_parent_directory(
    const wchar_t *path,
    wchar_t *directory_out,
    size_t directory_capacity)
{
    wchar_t *separator;
    size_t length;

    if (path == NULL || directory_out == NULL || directory_capacity == 0) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return false;
    }

    length = wcslen(path);
    if (length + 1 > directory_capacity) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return false;
    }

    (void)wcscpy_s(directory_out, directory_capacity, path);
    separator = wcsrchr(directory_out, L'\\');
    if (separator == NULL) {
        separator = wcsrchr(directory_out, L'/');
    }

    if (separator == NULL) {
        SetLastError(ERROR_BAD_PATHNAME);
        return false;
    }

    if (separator == directory_out + 2 && directory_out[1] == L':') {
        separator[1] = L'\0';
    } else {
        *separator = L'\0';
    }
    return true;
}
