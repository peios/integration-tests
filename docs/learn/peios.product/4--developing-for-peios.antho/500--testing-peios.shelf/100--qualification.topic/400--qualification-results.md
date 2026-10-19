---
title: Qualification Results
type: reference
description: Interpret pass, failure, skipped cases, and recorded provenance.
---

The runner writes `run.json` before staging inputs and updates it as the run
progresses. It records suite commits, source hashes, supplied artifact
hashes, the composition, command, environment, and host details.
`stdout.jsonl` preserves Provium's per-file reports. `stderr.log` preserves
diagnostics, and `events.msgpack` preserves the event stream.

## Status and exit codes

| Status | Meaning | Exit code |
| --- | --- | --- |
| `prepared` | Inputs staged; no tests executed | 0 |
| `passed` | Every selected file reported successful cases | 0 |
| `incomplete` | At least one case was skipped | 3 |
| `failed` | Failure, timeout, missing report, or changed immutable input | 1 |
| `blocked` | Inputs could not be staged or validated | 2 |
| `interrupted` | The user interrupted execution | 130 |

Malformed arguments also return 2. A file with no reported cases is a
failure. Missing or duplicated file reports fail the run. A zero exit code
from Provium cannot hide failed cases or an incomplete report set.

`qualification` is true only for a passed system-mode run. It applies to
the recorded selection and supplied composition, not an entire OS release.
A harness run can pass while `qualification` remains false.

## Release evidence

Keep component fast checks, native conformance, system scenarios, and
release acceptance as separate gates. A successful host check establishes
runner behavior; it does not establish that a Peios image boots or that its
services work together.

Review the selected suites and skipped cases before accepting a release.
Also review the provenance declaration: hashes identify bytes, but do not
establish signing authority or prove the declared source-to-image mapping.
The runner records selected host executable hashes; host libraries, QEMU
data files, privileges, and kernel behavior remain environmental inputs.

Candidate overlays, such as `PT_EVENTD_ROOT`, must be supplied as hashed
artifacts. A test that requires an absent candidate overlay can skip; the
result then remains incomplete. Do not treat that as a successful release
gate or suppress the skip to make the result green.
