# peios-integration-tests

End-to-end tests for Peios: real images, booted in real VMs, driven by
[Provium](https://github.com/peios/provium).

Nothing here tests a source tree. Every test in this repo runs against a
**built, composed, signed Peios image** — the same artefacts a user would
install. That is the whole point of the repo: the tree has good unit
coverage and a large kernel conformance suite, and neither of them can tell
you whether a booted system logs a user on.

> **Status: greenfield.** The shape is being designed before the volume
> arrives. `../test-suite` (2,175 kernel cases) is expected to migrate here
> once that shape holds — but not before.

## Where this sits

| Tier | Question it answers | Runner |
|---|---|---|
| Unit | does the code I wrote work | `cargo test` / `go test`, per repo |
| Kernel conformance | does the kernel match PCSA/TRM | `test-suite/`, agent-only VM |
| **System conformance** | **does a booted Peios behave** | **this repo** |
| Release gate | does *this medium* install and boot | this repo, against `dist/` |

The two right-hand tiers are the same suite pointed at different artefacts.
A release gate is not a separate set of tests; it is these tests run against
the ISO instead of a development build.

## Shape

A **testset** is a directory holding a peiso spec and the tests that run
against the image it builds.

```
tests/
  authd/
    vm.toml            peiso spec: what this testset's image contains
    logon.test.lua     the tests
```

Each testset composes **only the packages it needs**. `peios-experimental`
— the shipping edition — pulls in atriumd, netd, resolvd, eventd and
eighteen firmware packages; booting all of that to exercise a logon path is
slow and couples every test to every component. Instead testsets build on a
minimal `peios-testbase` edition and add what they are testing:

```toml
[baseline]
edition = "TestBase"

[[package]]
name = "authd"
[[package]]
name = "lpsd"

[registry]
add = ["authd-service", "lpsd-service", "lpsd-first-account"]
```

peiso requires `baseline.edition`, and that is the right constraint rather
than one to loosen: an edition is precisely "a named package set plus its
registry seeds", which is exactly what a testset is. Per-testset *editions*
are not needed — a spec's `[[package]]` and `[registry]` keys tune a shared
base, so `peios-testbase` is the only new edition package.

## Citing what a test verifies

Every test names the documented statement it verifies, so a change to
behaviour can find its tests and a coverage report can find the gaps.

Peios documentation comes in two classes and **a failing test means
different things in each**:

| Cited | A failure means | What you do |
|---|---|---|
| a PCSA book (`PSPK`, `PGSS`, `PCDS`, `PSPU`) | the code violates a normative contract | fix the code |
| a TRM (`Kernel TRM`, `peinit TRM`, …) | behaviour changed | was it deliberate? if so, update the TRM and the test together |

That distinction is carried by the citation itself — no extra field. It
matters because a TRM is *descriptive*: it records the true state of the
component, so a test derived from one is a change detector, and the honest
resolution of a red light is sometimes to update the manual.

Citations are **Named Citations** (Trail TRA-2, adopted in PEI-566): an
anchor on an individual statement, cited as e.g.
`Kernel TRM *copy-up.preserves-ownership`. Until that ships, cite the
article (`Kernel TRM §4.12`) and name the statement in prose beside it, which
is what Conventions §5.3 already permits.

A citation is a **pointer, not a copy**. `test-suite` transcribed 3,443
statements into a matrix and the copies rotted when the documents changed;
nothing here restates what a document says.

## Deliberately unsettled

Recorded so they are decided rather than defaulted into:

- **Guest control channel.** Provium's agent gives Layer-0 syscall
  determinism but knows nothing about services; `dwed` gives structured
  exec with real exit codes and separated stderr, but only exists on `-dwe`
  media. Probably both. If `dwed`, then `as <principal>` (deferred from
  PEI-477 v1) stops being optional — most system-conformance cases are
  *negative*, and need an ordinary principal to be denied.
- **`peiso root` or `peiso iso` per testset.** `root` is fast but boots by a
  path no real user takes; `iso` exercises live-boot and the real medium.
  Likely `root` for testsets, `iso` for the release gate.
- **Change-driven selection.** Tests carrying a `touches` metadata field so
  a change to one component runs only the testsets it can affect. Provium
  already supports this (`--tag-meta KEY=VALUE`); the open part is deriving
  the values from each image's `compose.lock.toml` rather than hand-writing
  them. Deferred until there are enough tests to learn the shape from.

## Licence

MIT. See [LICENSE](LICENSE).
