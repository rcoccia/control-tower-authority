---
name: assess-cloud-workload
description: Elicit RelayEU Azure workload, environment, region, and cost-control facts.
---

# Assess cloud workload

Use this advisory interview to collect typed facts. It does **not** select
mandatory policy, grant a waiver, or author normative policy.

Ask for:

1. `platform`: is the workload `azure`?
2. `environment`: is it `dev`, `test`, or another stated value?
3. Which services, EU regions, managed identities, private data paths, and
   Bicep sources are proposed?
4. What is the EUR estimate and what changes to topology, SKU, or region are planned?

Summarize supplied facts and evidence gaps. Refer to `CCA-001` **Applicability**
and **Required properties**, and to `FIN-006` **Applicability** and
**Expected evidence**, without deciding whether either policy is mandatory.

For property detail, read `policies/cloud/CCA-001.md` and
`policies/finops/FIN-006.md`.
