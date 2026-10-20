---
title: Composition Format
type: reference
description: Supplied artifact and profile fields for the qualification runner.
---

A composition is a JSON object with `format` set to `1`.
Paths in `artifacts` are absolute or relative to the composition file.
Every artifact has a `path` and `sha256`. Other fields refer to an artifact
with an object such as `{"artifact": "kernel"}`.

## Fields

| Field | Meaning |
| --- | --- |
| `mode` | `system` by default; `harness` for local runner checks |
| `artifacts` | Named regular files or directory trees and their hashes |
| `runner` | Artifact reference for the executable Provium runner |
| `components` | Image component names mapped to exact Git commit IDs |
| `profiles` | Named boot profiles using recorded artifact references |
| `host_tools` | Executable names mapped to supplied artifact references |
| `guest_tools` | Test tool names with `unsigned` and optional `signed` inputs |
| `environment` | Explicit `PT_*` and supported `*_TEST_*` artifacts |
| `packages` | Optional declared package identities and manifest references |
| `file_timeout_seconds` | Per-file timeout; default 300 seconds |

System mode requires a declared component composition, boot profiles, and a
recorded `qemu-system-x86_64` executable. Harness mode uses Provium's local
backend, skips VM host preflight, and never produces OS qualification.
The host runtime remains a dependency in either mode. Local mode requires
selected test manifests to declare `harness_only: true`; ordinary native
suites cannot run on the local backend.

The image composition is an operator declaration. The runner does not
inspect an image to prove that its binaries came from those commits.
Package declarations use `name`, `version`, `arch`, and `manifest`.
The runner checks that each supplied manifest has the declared identity;
it does not resolve dependencies, install packages, or verify image contents.

## Profile inputs

A profile accepts `kernel`, `initrd`, `root`, `cmdline_file`, and
`agent_overlay_path` as artifact references. It also accepts `cmdline`,
`guest_os`, `inject_agent`, and `agent_boot_timeout` as ordinary values.
Every profile needs a kernel or a root containing one. Agent injection
requires an explicit agent overlay.

A `disks` entry accepts `path`, `id`, `readonly`, and `mediated`.
Its path is an artifact reference. Writable disks use separate working
copies; read-only media keep their supplied snapshot. Final working-disk
hashes are recorded separately from original input hashes.

Build commands and profile discovery directories are rejected. The runner
passes `--no-build` to Provium and writes its own explicit configuration.
The historical `build.sh` and `sign.sh` helper names resolve supplied guest
tools; they do not build or sign anything.

## Hashes and storage

A file hash is SHA-256 of its bytes. A directory hash covers sorted relative
paths, modes, file hashes, and link targets using the runner's canonical
JSON encoding. Use `peios-qualify hash` for trees. Links must be relative and
remain inside the tree. Special files and symlink artifact roots are rejected.

Each run copies and verifies supplied artifacts before execution. Keep
enough disk space for those copies and writable disk snapshots. The output
directory must not already exist. Preserve the result directory with the
release evidence; its hashes are useful only while the corresponding inputs
remain available.

Candidate binary inputs include `PEINIT_TEST_BINARY`, `TRUSTD_TEST_BINARY`,
`LOREGD_TEST_BINARY`, `NETD_TEST_BINARY`, `RESOLVD_TEST_BINARY`,
`NSS_NET_TEST_BINARY`, and `NSS_IDENTITY_TEST_BINARY`. Service seed inputs
use `NETD_TEST_SERVICE` or `RESOLVD_TEST_SERVICE`. All are artifact
references.
The resolver probe uses `guest_tools.pt-nss.unsigned`; its source and dynamic
linking requirements are in the resolver's integration bundle.
