# Contributing

## Policy-owner flow

Policy and catalog changes are PR-only. Open a focused pull request, update
the affected policy version, its digest in `manifest.json`, and any stable
property identifiers. `@rcoccia` must approve changes covered by
`CODEOWNERS`. The validation workflow must pass before merge.

Generic interview skills are distributed with Control Tower (or a future
organization-specific kit), not this Authority repository. Do not add skills
or runtime skill-download mechanisms here.

## Releases

Use semantic versions: increment PATCH for clarifications that preserve policy
meaning, MINOR for additive compatible content, and MAJOR for changed or
removed requirements. After merge, create a signed or annotated release tag
for the catalog version. Released tags are immutable for this demo: publish a
new version rather than moving or rewriting one.

## Consumer pinning

Consumers pin a release tag **and** its resolved commit, retain the
`manifest.json` policy SHA-256 values, and validate canonical policy bytes:

```text
tag -> immutable commit -> manifest digest -> UTF-8/LF policy bytes
```

The digest contract rejects UTF-8 BOMs and invalid UTF-8, canonicalizes CRLF
and bare CR line endings to LF, and preserves all other bytes, including final
newlines. `.gitattributes` enforces LF checkout for repository text.

This process provides demonstrable GitHub repository provenance only; it does
not create legal or cryptographic institutional authenticity.
