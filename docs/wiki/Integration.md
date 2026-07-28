# Integration

## Required sequence

1. Build and sign the x64 driver package for the supported Windows release.
2. Install and start the `AcTelemetry` kernel service.
3. Start the protected application and retain its PID and creation identity.
4. Start the collector with:

   ```powershell
   anticheat.exe `
     --pid <pid> `
     --require-kernel `
     --interval-ms 5000 `
     --log anticheat-events.jsonl
   ```

5. Forward complete JSONL records without reserialization.
6. Verify retained segments with `tools/verify_log.py`.
7. Correlate driver, scanner, process-identity, queue-health, and session
   signals on the server.
8. Stop the collector before unloading or upgrading the driver.

## Earliest-event capture

For launchers that must capture image loads before application initialization:

1. create the process suspended;
2. obtain the process ID and creation time;
3. start the collector with `--require-kernel`;
4. wait for `kernel_driver_connected`;
5. resume the initial application thread.

Image mappings completed before target registration are not replayed by the
driver. The user-mode inventory supplies the current module state on the next
scan.

## Compatibility contract

Reject a session when:

- driver protocol version differs from the collector;
- structure sizes do not match;
- an event batch is truncated or misaligned;
- a required driver request fails;
- the target process identity changes;
- kernel queue drops increase without an explicit degraded-mode policy.

The full ABI is documented in
[driver-integration.md](https://github.com/amandykovxd/anticheat/blob/main/docs/driver-integration.md).
