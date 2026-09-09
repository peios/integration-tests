# peios-integration-tests

End-to-end tests for Peios: real images, booted in real VMs, driven by
[Provium](https://github.com/peios/provium).

Nothing here tests a source tree. Every test in this repo runs against a
**built, composed, signed Peios image** — the same artefacts a user would
install. That is the whole point of the repo: the tree has good unit
coverage and a large kernel conformance suite, and neither of them can tell
you whether a booted system logs a user on.

> **Status: the migration is done.** The retired `test-suite` (2,175
> kernel cases and a hand-copied statement matrix) has been replaced by the
> testsets here, which cite the TRMs instead of transcribing them. There is
> no lockfile: every testset composes its image from the same package
> repository the release media are built from, so the kernel under test is
> the kernel that ships.

## Where this sits

| Tier | Question it answers | Runner |
|---|---|---|
| Unit | does the code I wrote work | `cargo test` / `go test`, per repo |
| Kernel conformance | does the kernel match PCSA/TRM | this repo, `kernel-only` profile: agent-only VM |
| **System conformance** | **does a booted Peios behave** | **this repo** |
| Release gate | does *this medium* install and boot | this repo, against `dist/` |

The two right-hand tiers are the same suite pointed at different artefacts.
A release gate is not a separate set of tests; it is these tests run against
the ISO instead of a development build.

## What a run needs

Nothing here is vendored; a run assembles its images from tools and
packages it expects to find. Missing any of these, `provium` builds the
image and then dies at the first boot with an exit code of 1 and no test
counted.

- **Provium, with its agent overlay.** The overlay is provium's build
  artefact (`scripts/build-overlay.sh` in that repo, needing the musl
  target, cpio and gzip); provium looks for it beside its binary or in a
  source checkout's `dist/`. The `peinit` and `prelude` profiles resolve
  it the same way, then fall back to a sibling checkout at
  `../provium/dist/`; `PROVIUM_OVERLAY` overrides all of it.
- **The package pool.** `peiso.toml` names one repository,
  `file://../pkgs/_pkgsOut_/`, the sibling `pkgs` checkout's local output
  with its dev signing key. Until `pkgs.peios.org` is live that is the
  only source, and it exists only on a machine that has built the
  packages.
- **KVM, QEMU, iproute2, nftables, peiso** — provium's own pre-flight
  lists them.

The two sibling-checkout assumptions are the ones that stop a fresh
clone from running today. Both are pointed at by a single setting each
(`PROVIUM_OVERLAY`, the repository URL in `peiso.toml`), so they are
configuration, not structure.

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

### When the component has no book

Some components have no document a citation can point at. Everything
published about prelude, the initramfs PID 1, lives in *topics* — task
docs — and Trail rejects an anchor outside a book, deliberately: a
citation is addressed through its book, so an anchor anywhere else could
never be cited.

Where that is the case, the suite cites an **inventory extracted from the
code**: a numbered list of the component's observable behaviours, each
with its evidence in the source and a note saying whether any published
page states it. Tests cite `prelude <claim-name>`, and the names are
shaped like anchors so that the day the component gains a book, adopting
them is a rename.

Read a failure the way you would read a TRM's: the inventory is
descriptive, so a red light says behaviour changed and the honest
resolution is sometimes to update the inventory. But it carries one
warning a TRM does not. An inventory is derived from the implementation,
so it agrees with the implementation by construction — it can tell you
that behaviour *changed*, never that the behaviour was *right*. Its own
notes are what carry that: a claim marked as stated by no published page
is a claim nobody has ever reviewed.

This is a stopgap rather than a pattern to spread. A component worth a
conformance suite is usually worth a book.

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
