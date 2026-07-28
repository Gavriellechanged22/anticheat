# Technical Support

## Supported requests

Public support covers:

- collector and driver build failures;
- IOCTL protocol compatibility;
- launcher and process-registration integration;
- JSONL event parsing and integrity-chain verification;
- documented CLI behavior;
- supported Windows architecture behavior;
- reproducible performance or queue-capacity defects.

Account enforcement, game-specific rules, production certificate issuance,
driver signing approval, private deployment infrastructure, and third-party
product compatibility certification are outside the repository support scope.

## Support channels

Use the channel that matches the request:

- [Defect report](https://github.com/amandykovxd/anticheat/issues/new?template=bug_report.yml)
  for reproducible incorrect behavior;
- [Engineering proposal](https://github.com/amandykovxd/anticheat/issues/new?template=feature_request.yml)
  for a bounded contract or implementation change;
- [Q&A Discussions](https://github.com/amandykovxd/anticheat/discussions/categories/q-a)
  for integration questions;
- [private security advisory](https://github.com/amandykovxd/anticheat/security/advisories/new)
  for a vulnerability.

Do not use public issues or discussions for kernel crash dumps, credentials,
signing material, private paths, user identifiers, or unreleased product data.

## Required diagnostic data

Include:

- repository commit SHA or release version;
- Windows build and architecture;
- Visual Studio, SDK, and WDK versions;
- collector architecture;
- driver signing and test-signing mode;
- exact command line with sensitive values removed;
- process exit code, Windows error code, or `NTSTATUS`;
- minimal reproduction steps;
- relevant sanitized JSONL events;
- validation commands already executed.

Kernel failures should include a private crash-dump reference, matching
symbols, active Driver Verifier flags, bugcheck code, and the first relevant
stack frame. Do not attach a memory dump to a public issue.

## Compatibility policy

The current code is a development implementation. Compatibility is defined by
the matrices in `README.md`, the shared protocol version in
`include/ac_driver_protocol.h`, and the event schema in
`docs/event-schema.md`.

Unsupported operating systems, unversioned protocol changes, modified driver
packages, and collectors built with warnings disabled are not accepted as
baseline defect reproductions.
