# Anticheat Telemetry Engineering Wiki

Anticheat Telemetry is a Windows Ring 0/3 process-integrity telemetry system.
It combines an optional WDM driver, a user-mode memory and module collector, a
versioned IOCTL ABI, and tamper-evident JSONL output.

The implementation produces telemetry only. Enforcement, account actions,
remote transport, and game-specific policy remain integrator-owned.

## Entry points

- [Architecture](Architecture)
- [Integration](Integration)
- [Kernel driver development](Kernel-Driver-Development)
- [Event pipeline](Event-Pipeline)
- [Security operations](Security-Operations)
- [Contribution workflow](Contribution-Workflow)
- [Engineering project](https://github.com/users/amandykovxd/projects/1)
- [Source repository](https://github.com/amandykovxd/anticheat)

## Current implementation

Implemented components:

- x64 `AcTelemetry.sys` WDM telemetry driver;
- x64 and Win32 `anticheat.exe` collector;
- fixed-size versioned buffered IOCTL protocol;
- process and image-load callback telemetry;
- module and executable-memory classification;
- event de-duplication and bounded scan budgets;
- JSONL rotation and SHA-256 integrity chain;
- x64, Win32, sanitizer, and CodeQL validation workflows.

Production deployment still requires WDK CI, Driver Verifier, HLK validation,
package signing, installer lifecycle tests, and a server-side correlation
service.
