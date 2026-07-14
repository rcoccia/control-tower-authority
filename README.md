# Control Tower Authority

This public repository is a **simulated external issuer** for bounded Control
Tower experiments. It publishes concise synthetic policies, a machine-readable
catalog. It is not a Control Tower product runtime and contains no interview
skills, runtime skill downloading, matcher, signatures, GitHub App, waiver
engine, or multi-Authority protocol.

Consumers obtain generic interview skills from their Control Tower distribution
or a future organization-specific kit. This repository is authoritative only
for policy documents and catalog bytes.

## Anonymous read model

Anyone may read a released policy anonymously. Consumers should pin both a
released tag and its resolved commit, then verify the policy digest in
[`manifest.json`](manifest.json):

```text
authority: github:rcoccia/control-tower-authority
release:   v0.1.0
commit:    <resolved immutable release commit>
policy:    policies/data/DR-009.md
sha256:    <manifest policy sha256>
```

For a local copy, run `python scripts/validate_authority.py`. Each manifest
SHA-256 is over policy bytes decoded as UTF-8 without a BOM, with CRLF and bare
CR line endings canonicalized to LF; all other bytes, including final-newline
semantics, are preserved. Invalid UTF-8 and BOM-prefixed files are rejected.
The validator checks this digest contract, catalog structure, tracked files,
property anchors.

## Owner and write model

Policy owners change the repository only through pull requests. `CODEOWNERS`
assigns `@rcoccia` ownership of policies, the catalog, and validation scripts.
Branch protection and required review are repository governance
controls configured on the default branch; see
[CONTRIBUTING.md](CONTRIBUTING.md) for the release process.

## Trust boundary and demo status

GitHub commits, tags, `CODEOWNERS`, pull requests, and branch protection
demonstrate repository governance and byte provenance for this demo. They do
**not** establish legal truth, institutional authority, cryptographic
authenticity, or a production compliance decision. Every policy here is
synthetic demo content and must not be treated as real organizational policy.
