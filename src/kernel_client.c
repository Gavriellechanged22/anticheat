#include "ac.h"

#include <bcrypt.h>
#include <inttypes.h>
#include <string.h>

#define AC_KERNEL_DRAIN_BATCH_LIMIT 8u

void ac_kernel_client_init(AcKernelClient *client)
{
    if (client == NULL) {
        return;
    }

    memset(client, 0, sizeof(*client));
    client->device = INVALID_HANDLE_VALUE;
}

bool ac_kernel_client_open(AcKernelClient *client)
{
    DWORD returned = 0;

    if (client == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return false;
    }

    ac_kernel_client_init(client);
    client->device = CreateFileW(
        AC_DRIVER_WIN32_DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (client->device == INVALID_HANDLE_VALUE) {
        return false;
    }

    if (BCryptGenRandom(
            NULL,
            (PUCHAR)&client->session_id,
            (ULONG)sizeof(client->session_id),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0 ||
        client->session_id == 0) {
        const DWORD error = ERROR_GEN_FAILURE;
        ac_kernel_client_close(client);
        SetLastError(error);
        return false;
    }

    if (!DeviceIoControl(
            client->device,
            IOCTL_AC_GET_VERSION,
            NULL,
            0,
            &client->version,
            (DWORD)sizeof(client->version),
            &returned,
            NULL)) {
        const DWORD error = GetLastError();
        ac_kernel_client_close(client);
        SetLastError(error);
        return false;
    }

    if (returned != (DWORD)sizeof(client->version) ||
        client->version.size !=
            (uint32_t)sizeof(client->version) ||
        client->version.protocol_version !=
            AC_DRIVER_PROTOCOL_VERSION ||
        client->version.event_size != sizeof(AcDriverEvent)) {
        ac_kernel_client_close(client);
        SetLastError(ERROR_REVISION_MISMATCH);
        return false;
    }

    return true;
}

void ac_kernel_client_close(AcKernelClient *client)
{
    if (client == NULL) {
        return;
    }

    if (client->device != NULL &&
        client->device != INVALID_HANDLE_VALUE) {
        if (client->session_id != 0 && client->session_registered) {
            (void)ac_kernel_client_set_target(client, 0);
        }
        CloseHandle(client->device);
    }
    ac_kernel_client_init(client);
}

bool ac_kernel_client_set_target(AcKernelClient *client, DWORD pid)
{
    AcDriverTargetRequest request;
    DWORD returned = 0;

    if (client == NULL ||
        client->device == NULL ||
        client->device == INVALID_HANDLE_VALUE) {
        SetLastError(ERROR_INVALID_HANDLE);
        return false;
    }

    memset(&request, 0, sizeof(request));
    request.size = (uint32_t)sizeof(request);
    request.protocol_version = AC_DRIVER_PROTOCOL_VERSION;
    request.target_pid = (uint32_t)pid;
    request.session_id = client->session_id;

    if (!DeviceIoControl(
            client->device,
            IOCTL_AC_SET_TARGET,
            &request,
            (DWORD)sizeof(request),
            NULL,
            0,
            &returned,
            NULL)) {
        return false;
    }
    client->session_registered = pid != 0;
    return true;
}

bool ac_kernel_client_get_stats(
    AcKernelClient *client,
    AcDriverStats *stats_out)
{
    DWORD returned = 0;

    if (client == NULL || stats_out == NULL ||
        client->device == NULL ||
        client->device == INVALID_HANDLE_VALUE) {
        SetLastError(ERROR_INVALID_HANDLE);
        return false;
    }

    memset(stats_out, 0, sizeof(*stats_out));
    if (!DeviceIoControl(
            client->device,
            IOCTL_AC_GET_STATS,
            NULL,
            0,
            stats_out,
            (DWORD)sizeof(*stats_out),
            &returned,
            NULL)) {
        return false;
    }

    if (returned != (DWORD)sizeof(*stats_out) ||
        stats_out->size != (uint32_t)sizeof(*stats_out) ||
        stats_out->protocol_version !=
            AC_DRIVER_PROTOCOL_VERSION ||
        (stats_out->session_id != 0 &&
         stats_out->session_id != client->session_id)) {
        SetLastError(ERROR_INVALID_DATA);
        return false;
    }
    return true;
}

static const char *ac_kernel_event_name(uint32_t type)
{
    switch (type) {
        case AC_DRIVER_EVENT_TARGET_CHANGED:
            return "kernel_target_changed";
        case AC_DRIVER_EVENT_PROCESS_CREATED:
            return "kernel_process_created";
        case AC_DRIVER_EVENT_PROCESS_EXITED:
            return "kernel_process_exited";
        case AC_DRIVER_EVENT_IMAGE_LOADED:
            return "kernel_image_loaded";
        default:
            return "kernel_event_unknown";
    }
}

static void ac_kernel_event_path(
    const AcDriverEvent *event,
    char *escaped_path,
    size_t escaped_capacity)
{
    wchar_t wide_path[AC_DRIVER_IMAGE_PATH_CHARS];
    char path_utf8[AC_DRIVER_IMAGE_PATH_CHARS * 3u];
    size_t index;

    for (index = 0; index < AC_DRIVER_IMAGE_PATH_CHARS; ++index) {
        wide_path[index] = (wchar_t)event->image_path[index];
    }
    wide_path[AC_DRIVER_IMAGE_PATH_CHARS - 1u] = L'\0';

    if (!ac_wide_to_utf8(
            wide_path,
            path_utf8,
            sizeof(path_utf8))) {
        (void)strcpy_s(
            path_utf8,
            sizeof(path_utf8),
            "<conversion-failed>");
    }
    (void)ac_json_escape(
        path_utf8,
        escaped_path,
        escaped_capacity);
}

static void ac_log_kernel_event(
    AcLogger *logger,
    const AcDriverEvent *event)
{
    char escaped_path[AC_DRIVER_IMAGE_PATH_CHARS * 6u];
    char details[4096];

    ac_kernel_event_path(
        event,
        escaped_path,
        sizeof(escaped_path));

    (void)snprintf(
        details,
        sizeof(details),
        "{\"driver_sequence\":%" PRIu64
        ",\"kernel_timestamp_100ns\":%" PRIu64
        ",\"type\":%u,\"flags\":%u,\"parent_pid\":%u,"
        "\"status\":\"0x%08x\",\"image_base\":\"0x%" PRIx64
        "\",\"image_size\":%" PRIu64 ",\"path\":\"%s\","
        "\"source\":\"kernel_callback\",\"verdict\":\"telemetry_only\"}",
        event->sequence,
        event->timestamp_100ns,
        event->type,
        event->flags,
        event->parent_process_id,
        (unsigned int)(uint32_t)event->status,
        event->image_base,
        event->image_size,
        escaped_path);

    ac_log_event(
        logger,
        AC_SEVERITY_INFO,
        ac_kernel_event_name(event->type),
        event->process_id,
        details);
}

bool ac_kernel_client_drain(
    AcKernelClient *client,
    AcLogger *logger,
    DWORD target_pid,
    uint64_t *events_out)
{
    AcDriverEvent events[AC_DRIVER_MAX_BATCH_EVENTS];
    uint64_t total = 0;
    unsigned int batch;

    if (client == NULL || logger == NULL ||
        client->device == NULL ||
        client->device == INVALID_HANDLE_VALUE) {
        SetLastError(ERROR_INVALID_HANDLE);
        return false;
    }

    for (batch = 0; batch < AC_KERNEL_DRAIN_BATCH_LIMIT; ++batch) {
        DWORD returned = 0;
        size_t count;
        size_t index;

        if (!DeviceIoControl(
                client->device,
                IOCTL_AC_READ_EVENTS,
                NULL,
                0,
                events,
                (DWORD)sizeof(events),
                &returned,
                NULL)) {
            return false;
        }

        if (returned % (DWORD)sizeof(AcDriverEvent) != 0) {
            SetLastError(ERROR_INVALID_DATA);
            return false;
        }

        count = returned / (DWORD)sizeof(AcDriverEvent);
        for (index = 0; index < count; ++index) {
            if (events[index].size !=
                    (uint32_t)sizeof(AcDriverEvent) ||
                events[index].protocol_version !=
                    AC_DRIVER_PROTOCOL_VERSION) {
                SetLastError(ERROR_INVALID_DATA);
                return false;
            }
            ac_log_kernel_event(logger, &events[index]);
            ++total;
        }

        if (count < AC_DRIVER_MAX_BATCH_EVENTS) {
            break;
        }
    }

    {
        AcDriverStats stats;
        if (!ac_kernel_client_get_stats(client, &stats)) {
            return false;
        }

        if (stats.events_dropped > client->last_dropped) {
            char details[512];
            (void)snprintf(
                details,
                sizeof(details),
                "{\"events_dropped\":%" PRIu64
                ",\"newly_dropped\":%" PRIu64
                ",\"queue_depth\":%u,\"queue_capacity\":%u}",
                stats.events_dropped,
                stats.events_dropped - client->last_dropped,
                stats.queue_depth,
                stats.queue_capacity);
            ac_log_event(
                logger,
                AC_SEVERITY_MEDIUM,
                "kernel_event_queue_overflow",
                target_pid,
                details);
        }
        client->last_dropped = stats.events_dropped;
    }

    if (events_out != NULL) {
        *events_out += total;
    }
    return true;
}
