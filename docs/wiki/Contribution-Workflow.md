# Contribution Workflow

## Change path

1. Select a `good first issue`, `help wanted` issue, or approved proposal.
2. Create a branch from the current `main`.
3. Implement one bounded technical change.
4. Run the required architecture and sanitizer validation.
5. Open a pull request with the exact commands and results.
6. Resolve review conversations and update stale validation.
7. Obtain code-owner approval.
8. The repository owner merges the accepted change.

Only `amandykovxd` can update `main`. Contributors use forks or feature
branches. GitHub attributes merged commits to their authors.

## Required checks

- Windows x64 collector;
- Windows Win32 collector;
- portable core under AddressSanitizer and UndefinedBehaviorSanitizer;
- CodeQL C/C++ analysis;
- protocol and documentation updates for interface changes.

Kernel changes additionally require WDK build evidence and an analysis of
IRQL, lifetime, unload, queue, and IOCTL behavior.

See
[CONTRIBUTING.md](https://github.com/amandykovxd/anticheat/blob/main/CONTRIBUTING.md)
for the complete contract.
