# macOS Integration

## Scope

The macOS collector is a user-mode telemetry component for Apple Silicon and
Intel Macs. It uses public `libproc` interfaces and does not install a kernel
extension, request a Mach task port, read target memory, modify the target, or
make enforcement decisions.

## Build

Requirements:

- macOS with Xcode Command Line Tools;
- CMake 3.24 or newer;
- a C11 compiler.

```bash
cmake --preset macos
cmake --build --preset macos-release
ctest --preset macos-release
cmake --install out/build/macos --prefix out/install/macos
```

The installed executable is `out/install/macos/bin/anticheat`.

## Runtime contract

```bash
./out/install/macos/bin/anticheat --pid <pid> --once --log events.jsonl
./out/install/macos/bin/anticheat --process <name> --interval-ms 5000
./out/install/macos/bin/anticheat --self --once --quiet
```

The collector records:

- executable path and process start time;
- executable virtual-memory region counts;
- anonymous executable mappings;
- writable and executable mappings;
- scan completion and target lifecycle.

The JSONL envelope and hash-chain format match the shared event schema.
macOS-specific records use `platform: "macos"` and
`metadata_api: "libproc"`.

## Permissions and limitations

The implementation intentionally does not call `task_for_pid`. Metadata for
unrelated or protected processes may be unavailable because of process
ownership, System Integrity Protection, sandboxing, or privacy controls.
A failed metadata query is reported as an access failure; the collector does
not attempt to bypass platform policy.

The Windows `AcTelemetry.sys` driver, IOCTL protocol, `--kernel`, and
`--require-kernel` options are unavailable on macOS.
