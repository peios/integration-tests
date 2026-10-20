# Peios integration tests

This repository owns cross-component scenarios and the runner that assembles
component conformance suites. Components own their contract tests, fixtures,
and native checks. Provium owns generic VM machinery.

Use Python 3.11 or later and Git on Linux. Run the orchestration checks with:

```sh
./bazel test //:check
```

List the recorded suites, then run a component against supplied artifacts:

```sh
./peios-qualify list --lock suites.lock.json --suite authd
./peios-qualify run --lock suites.lock.json --suite authd \
  --composition /path/to/composition.json --output /path/to/fresh-run
```

Omit `--suite` to run every recorded suite. Repeat it to select several.
Every repository in `suites.lock.json` must be available at its recorded local
path, with the recorded Git objects. A checkout's branch does not select tests.
The runner reads committed files directly; it does not use uncommitted files.

Read the [test ownership guide](docs/learn/1--peios.shelf/peios.product/300--developing-for-peios.antho/500--testing.shelf/100--qualification.topic/100--test-ownership.md)
and [run guide](docs/learn/1--peios.shelf/peios.product/300--developing-for-peios.antho/500--testing.shelf/100--qualification.topic/200--running-conformance.md).
`examples/composition.json` shows the supplied-artifact contract.
Replace its placeholder paths, hashes, and revisions before use.

`run.json`, `stdout.jsonl`, `stderr.log`, and `events.msgpack` record a run.
Skipped cases produce an incomplete result. A local harness check does not
qualify a Peios image, and selected suite results do not certify an OS release.

The runner does not build images, resolve packages, or sign test tools. Supply
images and tools prepared for the selected tests, including their trust policy.
Hashes identify inputs; they do not verify signatures or prove image contents.
The host runtime remains a recorded dependency, not a hermetic environment.

The migration preserves all 604 imported test files. `migration-map.json`
records their original paths and hashes. The four central files include one
legacy `.peipkg` scenario; that scenario does not qualify PPK packages.
Archived image recipes under `docs/archive/legacy-image-builders/` are
historical reference and are excluded from active suite manifests.

Source updates follow PSC commit conventions. Keep `suites.json` as the source
catalog; refresh `suites.lock.json` deliberately after reviewing component
commits. Do not update pins as a side effect of running tests.

To check the real Provium command adapter without booting a VM:

```sh
PYTHONPATH=. python3 checks/smoke_provium.py \
  --runner /path/to/provium --evidence /path/to/fresh-evidence
```

The smoke check verifies pass and skip results and records the runner hash.
It does not replace the native conformance run.
