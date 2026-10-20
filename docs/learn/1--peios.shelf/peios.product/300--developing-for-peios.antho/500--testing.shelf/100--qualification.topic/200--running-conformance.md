---
title: Running Conformance Tests
type: how-to
description: Run component or system suites against supplied, recorded inputs.
---

Run the host checks before using the qualification runner. Use Python 3.11
or later and Git on a Linux host:

```sh
./bazel test //:check
```

A native run also needs a suitable QEMU host, the required privileges,
networking tools, and Peios images. Provium checks host prerequisites.
Prepare images outside the runner, with the fixtures and services described
by the selected suite. The archived profile recipes document those inputs.

## Prepare the composition

Copy `examples/composition.json`. Replace every placeholder with a supplied
path, its hash, and the exact component source revisions in the image.
Calculate a file or directory hash with:

```sh
./peios-qualify hash /path/to/artifact
```

Supply signed guest tools when a test requests them. Their signatures must
match the image's trust policy. The runner checks hashes, not signatures;
verify signature authority when preparing the supplied artifacts.

Use `kernel-only` for kernel and network apparatus, `prelude` for early
boot, and `peinit` for full-system service tests. A component selection can
need more than one profile. Prelude tests also require `PT_MKIRF` to name a
recorded artifact; no sibling build or host-path fallback is used.

## Select and run tests

Keep all repositories named by the lock available, including helper owners.
The runner reads their recorded Git objects without switching branches.
List a component's test files:

```sh
./peios-qualify list --lock suites.lock.json --suite authd
```

Stage a run without starting Provium:

```sh
./peios-qualify prepare --lock suites.lock.json --suite authd \
  --composition /path/to/composition.json --output /path/to/prepared-run
```

Run with a fresh output directory. Avoid single quotes and control
characters in that path because the imported helpers use shell commands:

```sh
./peios-qualify run --lock suites.lock.json --suite authd \
  --composition /path/to/composition.json --output /path/to/run \
  --timeout-seconds 3600
```

Repeat `--suite` for several components. Select `system` for the central
scenarios; omit `--suite` for all test files. An empty selection is an error.
Slow cases are included. A timeout stops the runner and its child processes.

Component bundles also expose a `check-integration` script and a Bazel
`:check` target.
Set `PEIOS_QUALIFY` to the central executable and supply the same lock,
composition, and fresh output path. These entry points do not build images.

## Test a candidate

Commit the candidate suite and use a clean checkout. Add an explicit
`--candidate authd=/path/to/authd` to select its committed test source.
This overrides one suite pin and records the selected commit. It does not
replace the image or infer which binaries the image contains.

Update the supplied composition when testing candidate binaries. Keep the
test revision and image component revision distinct in the result record.
After reviewing permanent suite changes, refresh the lock deliberately:

```sh
./peios-qualify pin --catalog suites.json --output suites.lock.json
```

Review the lock diff before committing it. Pin updates are separate from
running tests and do not publish any repository.
