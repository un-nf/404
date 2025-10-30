# Contributing to 404

## Foreword

This project is not a charity for random pull requests. Random, anonymous PRs from strangers create legal, security, and product friction that can block the project's growth.

If you want to help, **join the team**. If you can't join the team, there are useful, safer ways to contribute short of code-ownership: detailed issues, reproducible test cases, and design proposals. We value long-term collaborators over one-off patches.

## TL;DR

**We do not want:**
- Random PRs from unknown authors.

**We want:**
- Developers who are willing to commit: join the team, sign contributor agreements, and help carry the design, security, and maintenance burden.
- If you can't join, open an issue, file a detailed bug, or submit test cases/examples rather than direct code changes.

**Contact to apply:** `404mesh@proton.me`

## Why Not Random PRs?

Accepting code from many individual contributors without an explicit legal agreement creates long-term problems:

### Operational Risk
This software intentionally manipulates traffic. We must control who can alter critical code paths (header manipulation, certificate handling, logging). Loose PR intake invites accidental or malicious changes.

### Security & Audit Cost
Every external contribution increases audit surface area. Unknown authorship means unknown intent. We must be able to perform code provenance checks and reproducible builds; that's easier when contributors are known and sign commitments.

### Product Integrity
A product-ready package needs an auditable, test-covered codebase. Random PRs increase technical debt and create onboarding friction when we try to harden the repo for distribution.

### Relicensing & Packaging Complications
If we decide later to change the license, dual-license, or build a commercial offering, every contributor's copyright needs to be accounted for. Without contributor agreements that explicitly license their contributions to the project owner, relicensing is technically and practically blocked.

## GPLv3 Implications

This repo is distributed under GPLv3. GPLv3 has practical consequences you need to understand before contributing:

### Viral Copyleft
Code distributed under GPLv3 requires derivative works to be licensed under GPLv3 as well. If we accept code from contributors under GPLv3, that code becomes part of the copyleft pool.

### Contributor Provenance Matters
When you submit code, you are effectively adding your copyright to the project. This is not cosmetic — it affects what the project can legally become later. We want you to be a part of the project, just reach out!

**Why this matters for 404:** We may want flexibility (commercial support, different distribution models, or dual-licensing) as the project matures. Accepting many anonymous GPLv3 contributions without clear assignment/licensing agreements permanently narrows future options and increases legal overhead.

> **Short legal note:** I'm not a lawyer. This is my understanding of how contributor copyright interacts with GPLv3. For binding legal advice, consult counsel.

## How You Can Contribute Without Becoming a Team Member

If you don't want to join full-time (or can't), but still want to help:

### Open an Issue
Clear description, reproduction steps, expected vs actual behavior, and sanitized logs.

### Submit Test Artifacts
Sanitized pcaps, small test pages, or sample flows that reproduce fingerprinting or header problems.

### Design Proposals
Write a clear design doc. Long-form thought and reproducible design is gold.

### Threat Models & Audits
Produce a one-page threat model, or a short audit checklist for a subsystem (header munging, CA handling, logging).

We will review and, when feasible, incorporate non-code contributions or give guidance on how to proceed safely.

## How to Join the Team

We are looking for people who will do more than patch: engineers who will own parts of the system.

### What We Expect

Team members should:

- Be comfortable with core systems code (Python, mitmproxy, networking, eBPF basics if relevant).
- Sign a contributor agreement (CLA) or assign copyright as a condition of code ownership / deep contribution.
- Use verifiable identities for commits (GPG-signed commits and traceable email).
- Participate in security triage and code review.
- Write tests and maintain CI for the components they own.
- Be willing to collaborate in an explicit governance model (maintainers, reviewers, release process).

### Onboarding Steps

1. **Email `404mesh@proton.me`** with a short pitch: your experience, why you want to join, and what subsystem you want to own.
2. **Provide a short technical sample** (link to a repo or a short code sample).
3. **We'll schedule a short technical conversation**; if accepted, we will present the contributor agreement and onboarding tasks.
