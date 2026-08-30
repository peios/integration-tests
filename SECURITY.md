# Security policy

Report vulnerabilities privately to **security@peios.org** — do not open a
public issue. The full policy is at
https://learn.peios.org/project/policies/security-policy/ and the
machine-readable form at
https://learn.peios.org/.well-known/security.txt.

## The images this repo builds are test images

Testset images are composed for observability, not for defence. They may
carry `peios-dwe` — which performs no authentication, so anything that can
reach its socket owns the machine as SYSTEM — and they may seed accounts
without passwords so a test can log on unattended.

None of that is in scope for a report: it is what a test image is for. They
are built into a local, git-ignored output directory and are never published.

What *is* in scope: anything here that weakens a machine not running these
tests, and any path by which a testset image or its seeds could reach
pkgs.peios.org or a release medium.
