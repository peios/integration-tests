---
title: Test Ownership
type: explanation
description: Where Peios tests, fixtures, and qualification machinery belong.
---

Keep a test beside the component whose contract it checks. A test that needs
a VM still belongs to that component if its assertions concern that
component's behavior. The VM is apparatus, not an ownership rule.

## Choose an owner

| Test or helper | Owner |
| --- | --- |
| Unit tests and isolated API checks | The component |
| Native contract tests using a real kernel | The component |
| Behavior across several real services | Integration Tests |
| Complete boot, upgrade, and release qualification | Integration Tests |
| Generic VM lifecycle and host utilities | Provium |
| Component-specific fixtures and helpers | The component |

For example, a resolver test using a stub network manager belongs to
resolvd. A scenario asserting behavior across real resolvd and netd belongs
to Integration Tests. An authd event test can use eventd as observation
apparatus while checking authd's documented event contract.

## Keep one maintained copy

A component exports its suite through `tests/integration/suite.json`.
The kernel uses `peios/tests/integration/suite.json`. The manifest lists
owned test files and maps helper and fixture sources into a virtual layout.
Cross-component scenarios have a manifest in the central repository.

The central `suites.lock.json` records each repository's exact commit and
manifest hash. The runner reads files from those Git objects and assembles
the layout in a fresh run directory. It rejects duplicate export paths.
Shared helpers come from their owning repositories, not copied snapshots
inside each consumer.

Keep fast checks in ordinary component CI. Run native conformance with
supplied images and tools. Use the central runner for both component and
system selections, so both produce the same provenance and result format.

## Preserve migration evidence

The migration map accounts for 604 imported test files. Imported assertions
retain their historical specification references. One resolver test moves
its inline probe into a supplied tool; its assertions remain unchanged. The
map records source paths and hashes; helper adaptations are listed
separately in `migration-adaptations.json`.

The central legacy package-event scenario exercises `.peipkg`. It does not
establish compatibility with PPK blobs and manifests. Archived recipes
preserve fixture requirements without activating retired image builders.
