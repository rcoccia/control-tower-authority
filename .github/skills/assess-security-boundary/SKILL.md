---
name: assess-security-boundary
description: Elicit RelayEU ingress and Azure service-boundary security facts.
---

# Assess security boundary

Use this advisory interview to collect typed facts. It does **not** select
mandatory policy, grant a waiver, or author normative policy.

Ask for:

1. `platform`: is the workload `azure`?
2. `internet_ingress`: is ingress enabled (`true` or `false`)?
3. How are TLS, Entra status API access, ES256/JWKS validation, replay
   detection, and safe logging implemented?

Summarize supplied facts and evidence gaps. Refer to `SEC-014` **Applicability**,
**Required properties**, and **Expected evidence** without deciding whether it
is mandatory.

For property detail, read `policies/security/SEC-014.md`.
