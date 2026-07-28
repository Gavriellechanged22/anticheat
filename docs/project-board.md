# Engineering Project Contract

## Project scope

GitHub Project
[`amandykovxd/projects/1`](https://github.com/users/amandykovxd/projects/1)
tracks work required to move Anticheat Telemetry from a development sensor to
a qualified Windows Ring 0/3 integration.

The board covers:

- kernel driver build and reliability;
- user-mode collector behavior;
- shared protocol and event contracts;
- signing, packaging, and lifecycle;
- launcher and application identity integration;
- event delivery and server correlation;
- security, compatibility, and performance qualification.

## Field model

| Field | Type | Values |
| --- | --- | --- |
| Status | Single select | Backlog, Ready, In progress, In review, Done |
| Priority | Single select | Critical, High, Normal |
| Area | Single select | Kernel, Collector, Protocol, Delivery, Integration, Backend, Validation |
| Milestone | Single select | Foundation, M1 Kernel CI, M2 Reliability, M3 Package, M4 Session, M5 Manifest, M6 PE Integrity, M7 Transport, M8 Correlation, M9 Qualification |

## Status contract

- `Backlog`: scope is recorded but prerequisites or design decisions remain.
- `Ready`: acceptance criteria are complete and implementation can start.
- `In progress`: an assignee or linked branch is actively implementing the
  item.
- `In review`: an open pull request contains the implementation.
- `Done`: the pull request is merged, required checks pass, and documentation
  is updated.

Only the repository owner moves an item to `Done`.

## Priority contract

- `Critical`: blocks safe repository operation or an active release.
- `High`: blocks production qualification or a dependent roadmap milestone.
- `Normal`: scheduled capability or maintenance work without an immediate
  production blocker.

## Initial item registry

| Item | Status | Priority | Area | Milestone |
| --- | --- | --- | --- | --- |
| [#1 Version-reporting command](https://github.com/amandykovxd/anticheat/issues/1) | Ready | Normal | Collector | Foundation |
| [#2 CMake x64/Win32 presets](https://github.com/amandykovxd/anticheat/issues/2) | Ready | Normal | Delivery | Foundation |
| [#3 Pinned WDK build and INF validation](https://github.com/amandykovxd/anticheat/issues/3) | Ready | High | Kernel, Delivery | M1 Kernel CI |
| [#9 Driver reliability qualification](https://github.com/amandykovxd/anticheat/issues/9) | Backlog | High | Kernel, Validation | M2 Reliability |
| [#10 Signing and driver lifecycle](https://github.com/amandykovxd/anticheat/issues/10) | Backlog | High | Kernel, Delivery | M3 Package |
| [#11 Target session identity](https://github.com/amandykovxd/anticheat/issues/11) | Backlog | High | Protocol, Integration | M4 Session |
| [#12 Signed application manifest](https://github.com/amandykovxd/anticheat/issues/12) | Backlog | Normal | Collector, Integration | M5 Manifest |
| [#13 PE-aware integrity](https://github.com/amandykovxd/anticheat/issues/13) | Backlog | Normal | Collector, Validation | M6 PE Integrity |
| [#14 Authenticated event transport](https://github.com/amandykovxd/anticheat/issues/14) | Backlog | Normal | Backend, Integration | M7 Transport |
| [#15 Audit-only correlation service](https://github.com/amandykovxd/anticheat/issues/15) | Backlog | Normal | Backend | M8 Correlation |
| [#16 Compatibility and performance matrix](https://github.com/amandykovxd/anticheat/issues/16) | Backlog | Normal | Validation | M9 Qualification |

## Automation contract

Configure project workflows to:

1. add new repository issues labeled `roadmap`, `good first issue`, or
   `help wanted`;
2. set new items to `Backlog`;
3. move an item to `In progress` when an assignee or linked implementation
   branch is added;
4. move an item to `In review` when a linked pull request is opened;
5. move an item to `Done` only after merge to `main`;
6. retain closed, unmerged items for audit instead of deleting them.

Project automation does not replace branch protection, required status checks,
CODEOWNERS approval, or the owner-only update ruleset.
