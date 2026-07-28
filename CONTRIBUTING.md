# Contributing

## Contribution model

The repository accepts changes through pull requests.

- External contributors fork the repository, create a branch in the fork, push
  the branch, and open a pull request against `main`.
- Repository collaborators create a branch in this repository, push the
  branch, and open a pull request against `main`.
- Direct pushes, force pushes, and deletion of `main` are not part of the
  contribution workflow.
- The repository owner reviews and merges accepted pull requests.

GitHub lists an author as a repository contributor after a commit attributed
to that author is merged into the default branch. Repository write access is
not required for contributor attribution.

## Engineering scope

Accepted changes must preserve the telemetry-only security boundary described
in [SECURITY.md](SECURITY.md). The current project does not accept changes
that:

- expose arbitrary kernel or process-memory access;
- patch kernel or user memory;
- hook kernel dispatch tables, interrupts, or executable code;
- hide processes, modules, drivers, handles, files, or registry entries;
- terminate, suspend, or block processes from the kernel driver;
- add account-enforcement policy to the collector;
- add production signing credentials or private keys.

Changes outside this boundary require a separate design proposal, threat
model, protocol review, and maintainer approval before implementation.

## Branches and commits

Create branches from the current `main` branch:

```bash
git switch main
git pull --ff-only origin main
git switch -c <type>/<short-description>
```

Use one of these branch prefixes:

- `feat/` for a new capability;
- `fix/` for a defect correction;
- `test/` for test coverage;
- `docs/` for technical documentation;
- `build/` for build and CI changes;
- `refactor/` for behavior-preserving code changes.

Keep each commit buildable and limited to one technical purpose. Use the
commit form `<type>(<scope>): <summary>`, for example:

```text
fix(protocol): reject truncated event batches
```

Do not rewrite a shared branch after another contributor has based work on it.

## Build and test requirements

User-mode changes must pass:

```powershell
cmake -S . -B build -A x64
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

Changes affecting pointer width, structure layout, process enumeration, or
Windows API use must also pass the Win32 build:

```powershell
cmake -S . -B build-win32 -A Win32
cmake --build build-win32 --config Release
ctest --test-dir build-win32 -C Release --output-on-failure
```

Portable-core changes must pass with AddressSanitizer and
UndefinedBehaviorSanitizer on a supported Clang or GCC environment.

Kernel-driver changes must include:

- the Visual Studio, Windows SDK, and WDK versions used;
- a successful Release x64 WDK build;
- relevant `InfVerif`, static-analysis, or Driver Verifier output;
- IRQL, allocation-lifetime, callback-unload, and IOCTL-validation analysis;
- no new pageable operation in a callback path unless the callback contract
  explicitly permits it.

Protocol changes must update the driver, collector, compile-time ABI
assertions, protocol version when compatibility changes, event schema,
integration documentation, and malformed-input tests in the same pull
request.

## Pull request requirements

Every pull request must:

1. describe the technical problem and implementation;
2. identify the affected component and public contract;
3. link the relevant issue when one exists;
4. include reproducible validation commands and results;
5. update technical documentation for interface or behavior changes;
6. preserve warning-free builds with warnings treated as errors;
7. pass all required GitHub Actions checks;
8. receive approval from the code owner before merge.

The maintainer may request splitting a pull request when independent changes
cannot be reviewed or reverted separately.

## Issue selection

Issues labeled
[`good first issue`](https://github.com/amandykovxd/anticheat/labels/good%20first%20issue)
contain bounded tasks suitable for a first contribution. Issues labeled
[`help wanted`](https://github.com/amandykovxd/anticheat/labels/help%20wanted)
identify work for which external implementation is requested.

Comment on an issue before implementation when the work changes the kernel
driver, shared protocol, event schema, or integration contract.

## Security reports

Do not open a public issue for a vulnerability that could cause kernel memory
corruption, unauthorized device access, callback unload races, or IOCTL
validation bypass. Use a private GitHub security advisory as specified in
[SECURITY.md](SECURITY.md).
