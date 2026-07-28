#include "ac.h"

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

static volatile LONG g_stop_requested = 0;

static BOOL WINAPI ac_console_handler(DWORD control_type)
{
    if (control_type == CTRL_C_EVENT ||
        control_type == CTRL_BREAK_EVENT ||
        control_type == CTRL_CLOSE_EVENT) {
        InterlockedExchange(&g_stop_requested, 1);
        return TRUE;
    }
    return FALSE;
}

static void ac_print_usage(const wchar_t *program)
{
    fwprintf(
        stderr,
        L"Usage: %ls --process <game.exe> [--interval-ms <1000..3600000>] "
        L"[--log <events.jsonl>] [--once]\n",
        program);
}

static bool ac_parse_dword(
    const wchar_t *text,
    DWORD minimum,
    DWORD maximum,
    DWORD *value_out)
{
    wchar_t *end = NULL;
    unsigned long value;

    if (text == NULL || value_out == NULL || text[0] == L'\0') {
        return false;
    }

    value = wcstoul(text, &end, 10);
    if (end == text || *end != L'\0' || value < minimum || value > maximum) {
        return false;
    }

    *value_out = (DWORD)value;
    return true;
}

static bool ac_parse_options(int argc, wchar_t **argv, AcOptions *options)
{
    int index;

    memset(options, 0, sizeof(*options));
    options->interval_ms = 5000;
    options->log_path = L"anticheat-events.jsonl";

    for (index = 1; index < argc; ++index) {
        if (wcscmp(argv[index], L"--process") == 0 && index + 1 < argc) {
            options->process_name = argv[++index];
        } else if (wcscmp(argv[index], L"--interval-ms") == 0 &&
                   index + 1 < argc) {
            if (!ac_parse_dword(
                    argv[++index],
                    1000,
                    3600000,
                    &options->interval_ms)) {
                return false;
            }
        } else if (wcscmp(argv[index], L"--log") == 0 && index + 1 < argc) {
            options->log_path = argv[++index];
        } else if (wcscmp(argv[index], L"--once") == 0) {
            options->once = true;
        } else {
            return false;
        }
    }

    return options->process_name != NULL &&
           options->process_name[0] != L'\0';
}

static bool ac_wait_for_process(
    const AcOptions *options,
    AcLogger *logger,
    DWORD *pid_out)
{
    bool announced = false;

    while (InterlockedCompareExchange(&g_stop_requested, 0, 0) == 0) {
        if (ac_find_process_by_name(options->process_name, pid_out)) {
            return true;
        }

        if (!announced) {
            char process_name[MAX_PATH * 3];
            char escaped_process_name[MAX_PATH * 6];
            char details[1024];

            if (!ac_wide_to_utf8(
                    options->process_name,
                    process_name,
                    sizeof(process_name))) {
                (void)strcpy_s(
                    process_name,
                    sizeof(process_name),
                    "<conversion-failed>");
            }
            ac_json_escape(
                process_name,
                escaped_process_name,
                sizeof(escaped_process_name));

            (void)snprintf(
                details,
                sizeof(details),
                "{\"process_name\":\"%s\"}",
                escaped_process_name);
            ac_log_event(
                logger,
                AC_SEVERITY_INFO,
                "waiting_for_process",
                0,
                details);
            announced = true;
        }

        Sleep(1000);
    }

    return false;
}

int wmain(int argc, wchar_t **argv)
{
    AcOptions options;
    AcLogger logger;
    DWORD pid = 0;
    HANDLE process = NULL;
    wchar_t process_path[32768];
    wchar_t process_path_for_log[MAX_PATH];
    wchar_t game_directory[32768];
    wchar_t windows_directory[MAX_PATH];
    char process_path_utf8[MAX_PATH * 3];
    char escaped_process_path[MAX_PATH * 6];
    char details[4096];
    uint64_t scan_id = 0;
    bool process_path_truncated;
    int exit_code = EXIT_FAILURE;

    if (!ac_parse_options(argc, argv, &options)) {
        ac_print_usage(argv[0]);
        return 2;
    }

    if (!ac_logger_open(&logger, options.log_path, true)) {
        fwprintf(stderr, L"Cannot open log file: %ls\n", options.log_path);
        return 3;
    }

    (void)SetConsoleCtrlHandler(ac_console_handler, TRUE);
    ac_log_event(
        &logger,
        AC_SEVERITY_INFO,
        "agent_started",
        0,
        "{\"mode\":\"observe_only\",\"memory_write_access\":false}");

    if (!ac_wait_for_process(&options, &logger, &pid)) {
        exit_code = EXIT_SUCCESS;
        goto cleanup;
    }

    process = ac_open_process_for_scan(pid);
    if (process == NULL) {
        ac_log_win32_error(&logger, "open_process_failed", pid, GetLastError());
        goto cleanup;
    }

    if (!ac_get_process_path(
            process,
            process_path,
            sizeof(process_path) / sizeof(process_path[0]))) {
        ac_log_win32_error(&logger, "query_process_path_failed", pid, GetLastError());
        goto cleanup;
    }

    if (!ac_get_parent_directory(
            process_path,
            game_directory,
            sizeof(game_directory) / sizeof(game_directory[0]))) {
        ac_log_win32_error(&logger, "derive_game_directory_failed", pid, GetLastError());
        goto cleanup;
    }

    {
        const UINT windows_directory_capacity =
            (UINT)(sizeof(windows_directory) / sizeof(windows_directory[0]));
        const UINT windows_directory_length = GetWindowsDirectoryW(
            windows_directory,
            windows_directory_capacity);
        if (windows_directory_length == 0 ||
            windows_directory_length >= windows_directory_capacity) {
            ac_log_win32_error(
                &logger,
                "query_windows_directory_failed",
                pid,
                windows_directory_length == 0
                    ? GetLastError()
                    : ERROR_INSUFFICIENT_BUFFER);
            goto cleanup;
        }
    }

    process_path_truncated =
        wcslen(process_path) >=
        sizeof(process_path_for_log) / sizeof(process_path_for_log[0]);
    (void)wcsncpy_s(
        process_path_for_log,
        sizeof(process_path_for_log) / sizeof(process_path_for_log[0]),
        process_path,
        _TRUNCATE);
    if (!ac_wide_to_utf8(
            process_path_for_log,
            process_path_utf8,
            sizeof(process_path_utf8))) {
        (void)strcpy_s(
            process_path_utf8,
            sizeof(process_path_utf8),
            "<conversion-failed>");
    }
    ac_json_escape(
        process_path_utf8,
        escaped_process_path,
        sizeof(escaped_process_path));

    (void)snprintf(
        details,
        sizeof(details),
        "{\"path\":\"%s\",\"access\":[\"PROCESS_QUERY_INFORMATION\","
        "\"PROCESS_VM_READ\"],\"path_truncated\":%s}",
        escaped_process_path,
        process_path_truncated ? "true" : "false");
    ac_log_event(&logger, AC_SEVERITY_INFO, "target_opened", pid, details);

    while (InterlockedCompareExchange(&g_stop_requested, 0, 0) == 0) {
        AcScanStats stats;

        ++scan_id;
        if (!ac_scan_process(
                &logger,
                process,
                pid,
                game_directory,
                windows_directory,
                scan_id,
                &stats)) {
            const DWORD error = GetLastError();
            if (error == ERROR_INVALID_HANDLE ||
                WaitForSingleObject(process, 0) == WAIT_OBJECT_0) {
                ac_log_event(
                    &logger,
                    AC_SEVERITY_INFO,
                    "target_exited",
                    pid,
                    "{}");
                exit_code = EXIT_SUCCESS;
                goto cleanup;
            }

            ac_log_win32_error(&logger, "scan_failed", pid, error);
        }

        if (options.once) {
            exit_code = EXIT_SUCCESS;
            goto cleanup;
        }

        if (WaitForSingleObject(process, options.interval_ms) == WAIT_OBJECT_0) {
            ac_log_event(
                &logger,
                AC_SEVERITY_INFO,
                "target_exited",
                pid,
                "{}");
            exit_code = EXIT_SUCCESS;
            goto cleanup;
        }
    }

    exit_code = EXIT_SUCCESS;

cleanup:
    if (process != NULL) {
        CloseHandle(process);
    }
    ac_log_event(
        &logger,
        AC_SEVERITY_INFO,
        "agent_stopped",
        pid,
        "{\"terminated_target\":false}");
    ac_logger_close(&logger);
    return exit_code;
}
