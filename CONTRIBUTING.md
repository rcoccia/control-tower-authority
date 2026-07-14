# Contributing

## Policy-owner flow

Policy and catalog changes are PR-only. Open a focused pull request, update
the affected policy version, its digest in `manifest.json`, and any stable
property identifiers. `@rcoccia` must approve changes covered by
`CODEOWNERS`. The validation workflow must pass before merge.

## Releases

Use semantic versions: increment PATCH for clarifications that preserve policy
meaning, MINOR for additive compatible content, and MAJOR for changed or
removed requirements. After merge, create a signed or annotated release tag
for the catalog version. Released tags are immutable for this demo: publish a
new version rather than moving or rewriting one.

## Consumer pinning

Consumers pin a release tag **and** its resolved commit, retain the
`manifest.json` policy SHA-256 values, and validate the checked-out bytes:

```text
tag -> immutable commit -> manifest digest -> policy bytes
```

This process provides demonstrable GitHub repository provenance only; it does
not create legal or cryptographic institutional authenticity.
