# Event Schema

Schema version: `3` (`AC_SCHEMA_VERSION`).

The collector writes UTF-8 JSON Lines. Each line contains one complete JSON
object followed by `LF`. The writer flushes each record before writing the
next record.

## Envelope

```json
{
  "seq": 12,
  "timestamp": "2026-07-28T10:00:00.000Z",
  "severity": "info",
  "event": "kernel_image_loaded",
  "pid": 1234,
  "details": {},
  "chain": "8f14e45fceea167a5a36dedd4bea2543..."
}
```

| Field | Type | Contract |
| --- | --- | --- |
| `seq` | unsigned integer | Collector-local sequence. Starts at 1 for each collector instance. |
| `timestamp` | string | UTC ISO-8601 timestamp with millisecond precision. |
| `severity` | string | `info`, `low`, `medium`, or `high`. |
| `event` | string | Stable event identifier within the schema version. |
| `pid` | unsigned integer | Target PID, or `0` for collector-wide records. |
| `details` | object | Event-specific payload. |
| `chain` | string | Lowercase 64-character SHA-256 integrity value. |

Consumers must order records by `seq`. Wall-clock timestamps may move backward
or forward because of system time changes.

## Integrity chain

For exact record body bytes ending immediately before `,"chain":"..."}`:

```text
chain[i] = SHA256(chain[i-1] || body[i])
```

`log_segment_opened.details.chain_seed` contains the initial chain value for a
collector instance. Rotated segments retain sequence and chain continuity.
Verify segments from oldest to newest:

```powershell
python tools\verify_log.py events.jsonl.2 events.jsonl.1 events.jsonl
```

The chain detects retained-record modification, insertion, removal, and
reordering. It does not prevent complete log replacement by a principal that
controls the endpoint. Remote systems should persist sequence and chain-head
checkpoints during the session.

## Severity contract

| Severity | Technical meaning |
| --- | --- |
| `info` | Lifecycle, configuration, health, accounting, or raw telemetry. |
| `low` | Weak anomaly or operational degradation. |
| `medium` | Anomaly requiring correlation; known legitimate sources exist. |
| `high` | Strong process-integrity anomaly; still not an enforcement decision. |

Detection records include either `"verdict":"signal_only"` or
`"verdict":"telemetry_only"`.

## Collector lifecycle events

### `log_segment_opened`

Severity: `info`.

Fields:

| Field | Type |
| --- | --- |
| `agent` | string |
| `version` | string |
| `schema` | unsigned integer |
| `chain_algorithm` | `"sha256"` |
| `chain_seed` | 64-character hex string |
| `max_bytes` | unsigned integer |
| `generations` | unsigned integer |
| `reason` | optional string; `size_limit` after rotation |

### `agent_started`

Severity: `info`.

Fields:

| Field | Type | Values |
| --- | --- | --- |
| `agent` | string | `anticheat-collector` |
| `version` | string | collector semantic version |
| `schema` | unsigned integer | `3` |
| `mode` | string | `user_telemetry` or `hybrid_kernel_user_telemetry` |
| `memory_write_access` | boolean | `false` |
| `terminates_target` | boolean | `false` |
| `interval_ms` | unsigned integer | configured scan interval |
| `once` | boolean | one-scan mode |
| `scan_budget_ms` | unsigned integer | performance threshold |
| `repeat_interval_ms` | unsigned integer | de-duplication interval |
| `pointer_bits` | unsigned integer | `32` or `64` |

### `waiting_for_process`

Severity: `info`.

Fields:

- `process_name`: requested executable name.

### `wait_for_process_timed_out`

Severity: `info`.

Fields:

- `verdict`: `no_target`.

### `multiple_process_matches`

Severity: `low`.

Fields:

- `matches`: number of matching executable names;
- `selected_pid`: selected PID;
- `hint`: integration guidance.

Use `--pid` in production integrations to avoid name ambiguity.

### `target_opened`

Severity: `info`.

Fields:

- `path`;
- `granted_access`: hexadecimal Win32 access mask;
- `least_privilege`;
- `start_time_filetime`;
- `allow_roots`.

### `target_identity_mismatch`

Severity: `medium`.

The image path associated with the opened process does not match the requested
executable name. The collector does not scan the process.

### `allow_root_configured`

Severity: `info`.

Fields:

- `path`: one expected module root.

Directory membership is an operational classification, not cryptographic file
identity.

### `target_exited`

Severity: `info`.

The target process handle entered the signaled state.

### `agent_stopped`

Severity: `info`.

Fields:

- `scans`;
- `kernel_events`;
- `terminated_target`: always `false`;
- `log_write_failures`;
- `log_truncated_lines`;
- `exit_code`.

## Kernel transport events

### `kernel_driver_connected`

Severity: `info`.

Fields:

| Field | Type |
| --- | --- |
| `protocol_version` | unsigned integer |
| `event_size` | unsigned integer |
| `queue_capacity` | unsigned integer |
| `target_pid` | unsigned integer |

This record confirms protocol validation and successful target registration.

### `kernel_driver_open_failed`

Severity: `low`.

Standard Win32 error payload:

- `win32_error`;
- `message`.

In `--kernel` mode the collector continues with user-mode telemetry. In
`--require-kernel` mode it exits.

### `kernel_target_registration_failed`

Severity: `low`.

The driver rejected `IOCTL_AC_SET_TARGET`. The payload contains the Win32
error code returned by `DeviceIoControl`.

### Kernel callback event envelope

The following event identifiers use the same detail contract:

- `kernel_target_changed`;
- `kernel_process_created`;
- `kernel_process_exited`;
- `kernel_image_loaded`;
- `kernel_event_unknown`.

Fields:

| Field | Type | Contract |
| --- | --- | --- |
| `driver_sequence` | unsigned integer | Monotonic sequence assigned in the driver. |
| `kernel_timestamp_100ns` | unsigned integer | System time in 100-nanosecond intervals. |
| `type` | unsigned integer | `AcDriverEventType`. |
| `flags` | unsigned integer | `AC_DRIVER_EVENT_FLAG_*` bitmask. |
| `parent_pid` | unsigned integer | Available for process creation. |
| `status` | string | NTSTATUS formatted as hexadecimal. |
| `image_base` | string | 64-bit hexadecimal address. |
| `image_size` | unsigned integer | Mapped image size. |
| `path` | string | Bounded image path; may be empty. |
| `source` | string | `kernel_callback`. |
| `verdict` | string | `telemetry_only`. |

Driver event types:

| Value | Identifier |
| --- | --- |
| `1` | `AC_DRIVER_EVENT_TARGET_CHANGED` |
| `2` | `AC_DRIVER_EVENT_PROCESS_CREATED` |
| `3` | `AC_DRIVER_EVENT_PROCESS_EXITED` |
| `4` | `AC_DRIVER_EVENT_IMAGE_LOADED` |

`kernel_process_created` may describe a direct child of the registered target.
In that case the envelope `pid` is the child PID and `details.parent_pid` is
the registered target PID.

Driver event flags:

| Bit | Identifier |
| --- | --- |
| `0x00000001` | `AC_DRIVER_EVENT_FLAG_PATH_TRUNCATED` |
| `0x00000002` | `AC_DRIVER_EVENT_FLAG_SYSTEM_IMAGE` |
| `0x00000004` | `AC_DRIVER_EVENT_FLAG_PATH_UNAVAILABLE` |

### `kernel_event_queue_overflow`

Severity: `low`.

Fields:

- `events_dropped`: cumulative overwritten-event count;
- `newly_dropped`: increase since the previous statistics read;
- `queue_depth`;
- `queue_capacity`.

The driver overwrites the oldest event when the fixed queue is full.

### `kernel_event_read_failed`

Severity: `low`.

The IOCTL read or statistics request failed, or the returned protocol data was
malformed. The collector closes the driver handle after this record.

## User-mode scan events

### `scan_completed`

Severity: `info`.

Fields:

| Field | Type |
| --- | --- |
| `scan_id` | unsigned integer |
| `duration_ms` | unsigned integer |
| `modules` | unsigned integer |
| `module_list_truncated` | boolean |
| `modules_outside_allowed_roots` | unsigned integer |
| `regions_visited` | unsigned integer |
| `executable_regions` | unsigned integer |
| `suspicious_regions` | unsigned integer |
| `query_failures` | unsigned integer |
| `read_failures` | unsigned integer |
| `probe_bytes` | unsigned integer |
| `events_emitted` | unsigned integer |
| `events_suppressed` | unsigned integer |
| `dedup_entries` | unsigned integer |
| `dedup_saturated_events` | unsigned integer |

Consumers should monitor the expected event cadence. Missing
`scan_completed` records indicate a stopped collector, blocked collector, or
lost transport.

### `scan_budget_exceeded`

Severity: `low`.

Fields:

- `scan_id`;
- `duration_ms`;
- `budget_ms`;
- `breaches`: cumulative breach count.

### Operational failure events

Examples:

- `scan_failed`;
- `open_process_failed`;
- `query_process_path_failed`;
- `derive_game_directory_failed`;
- `wait_failed`;
- `context_init_failed`.

Win32 failure records contain:

- `win32_error`;
- `message`.

## Detection events

### `module_outside_allowed_roots`

Severity: `low`.

Fields:

| Field | Type |
| --- | --- |
| `scan_id` | unsigned integer |
| `path` | string |
| `base` | hexadecimal string |
| `size` | unsigned integer |
| `file_sha256` | string or `null` |
| `file_size` | unsigned integer |
| `reason` | `outside_allowed_roots` |
| `verdict` | `signal_only` |
| `first_seen_scan_id` | unsigned integer |
| `occurrences` | unsigned integer |
| `suppressed_since_last_report` | unsigned integer |

### `suspicious_executable_region`

Severity: `low`, `medium`, or `high`.

Fields:

| Field | Type |
| --- | --- |
| `scan_id` | unsigned integer |
| `base` | hexadecimal string |
| `size` | unsigned integer |
| `protect` | unsigned integer |
| `type` | `image`, `mapped`, `private`, or `unknown` |
| `backed_by_loaded_module` | boolean |
| `pe_header` | boolean |
| `pe_machine` | hexadecimal string |
| `content_sha256_4k` | string or `null` |
| `reason` | classification identifier |
| `verdict` | `signal_only` |
| `first_seen_scan_id` | unsigned integer |
| `occurrences` | unsigned integer |
| `suppressed_since_last_report` | unsigned integer |

Classification identifiers:

| Reason | Default severity | Meaning |
| --- | --- | --- |
| `image_not_in_loader_list` | `high` | Executable `MEM_IMAGE` region absent from the loader-visible module index. |
| `mapped_executable_outside_module` | `medium` | Executable mapped region outside known module ranges. |
| `private_executable` | `medium` | Executable private memory. |
| `private_writable_executable` | `medium` | Writable and executable private memory. |
| `writable_executable_inside_module` | `low` | Writable executable region inside a known module. |
| `executable_memory_unknown_type` | `medium` | Executable region with an unclassified memory type. |

An executable region outside a loader-visible module is emitted as `high` when
the bounded content probe finds a valid PE header.

## De-duplication

The collector emits a finding on first observation. It suppresses equivalent
findings until `--repeat-interval-ms` expires, then emits the finding with
updated occurrence counters.

Fingerprints:

- modules: case-insensitive path;
- executable regions with a PE header: bounded content hash;
- executable regions without a PE header: reason, protection, and size bucket.

The table contains 4096 entries. When saturated, findings are emitted without
suppression and `dedup_saturated_events` increases.

## Consumer requirements

Consumers must:

1. validate the schema version;
2. parse one line as one record;
3. order records by `seq`;
4. verify the integrity chain before relying on retained local records;
5. retain unknown event identifiers;
6. use `reason` as the stable classifier and `severity` as a configurable
   priority;
7. monitor sequence gaps, kernel dropped-event counters, and scan cadence;
8. correlate kernel and user-mode records by target PID, session, and time;
9. keep account or session enforcement outside the collector.
