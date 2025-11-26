# Contributing to 404

## The Philosophy

This project is not a public utility seeking random pull requests. It's a focused engineering effort. Anonymous, drive-by PRs create legal friction, security risks, and product debt that threaten the project's integrity and velocity.

We value long-term collaborators over one-off patches. If you want to contribute code, the path is to **join the team**. If you can't commit to that, there are still high-value ways to contribute, primarily through detailed issues, reproducible test cases, and structured design proposals.

## TL;DR

**We do not accept:**
- Unsolicited Pull Requests from unknown authors.

**We are looking for:**
- **Team Members:** Developers willing to commit, sign a contributor agreement, and share the burden of design, security, and maintenance for a specific subsystem.
- **Specialized Contributors:** If you can't join the team, provide high-signal contributions: file a detailed bug, submit a failing test case, or write a design proposal.

**To apply to the team, contact:** `404mesh@proton.me`

## Why This Policy?

Accepting code without a formal, trust-based relationship creates long-term problems:

### Operational Risk
This software intentionally terminates TLS and manipulates traffic at multiple layers. We must maintain strict control over who can alter critical code paths (the `STATIC` pipeline, certificate handling, eBPF logic). A loose PR process is an unacceptable risk.

### Security & Audit Cost
Every line of contributed code increases the audit surface. Unknown authorship means unknown intent. To maintain a defensible security posture, we require code provenance and GPG-signed commits from vetted team members.

### Product Integrity
Now at v1.0, the project has a stable core architecture. Contributions must align with the roadmap and architectural principles. Random PRs often diverge, creating technical debt and making it harder to harden the system for distribution.

### Licensing & Copyright
To maintain legal agility (for potential relicensing, commercial offerings, or partnerships), we must have a clean copyright chain. This requires a Contributor License Agreement (CLA) from anyone who contributes code, which is impractical to manage for drive-by PRs.

## How You Can Contribute (Without Joining the Team)

If you don't want to join full-time but still want to help, focus on contributions that don't involve direct code changes. This is where you can have the most impact.

### 1. Open a High-Quality Issue
- **Clear Title:** "Login fails on `example.com` due to CSP violation" is better than "stuff broke."
- **Reproduction Steps:** Provide a step-by-step guide to trigger the bug.
- **Expected vs. Actual Behavior:** What did you expect to happen? What happened instead?
- **Sanitized Logs:** Provide logs with `RUST_LOG=debug` enabled, removing any sensitive data.

### 2. Submit Test Artifacts & Profiles
The single most valuable non-code contribution is a new or improved **profile**.
- **Create a Profile:** Capture the fingerprint of a new browser or device. Document your process.
- **Submit a Failing Test Case:** Provide a sanitized `.pcap` file, a HAR file, or a self-contained HTML page that reproduces a fingerprinting leak or a breakage.
- **Validate a Profile:** Run an existing profile against a new fingerprinting service and document any detected inconsistencies.

### 3. Write a Design Proposal
If you have an idea for a new feature or a change to an existing one, write a one-page design document.
- **Problem:** What specific problem are you solving?
- **Proposed Solution:** How will you solve it? Include architectural diagrams if necessary.
- **Security Considerations:** How does your proposal affect the threat model?

We will review these contributions and, where appropriate, provide guidance or implement them ourselves.

## How to Join the Team

We are looking for engineers who will own a piece of the system, not just patch a bug.

### What We Expect
- **Subsystem Ownership:** Be prepared to become the expert on a part of the codebase (e.g., the HTTP/2 engine, the eBPF module, profile management, a specific pipeline stage).
- **Systems-Level Skill:** Be comfortable with Rust, networking fundamentals, and the core concepts of the project.
- **Commitment to Security:** Sign a contributor agreement (CLA), use a verifiable identity (GPG-signed commits), and participate in security reviews.
- **Write Tests:** All code contributions must be accompanied by tests. You are responsible for maintaining CI for the components you own.

### Onboarding Steps
1. **Email `404mesh@proton.me`:** Introduce yourself, explain why you want to join, and state which subsystem you're interested in owning.
2. **Provide a Work Sample:** Link to a relevant project, a detailed technical write-up, or a code sample that demonstrates your capabilities.
3. **Technical Conversation:** If there's a good fit, we'll schedule a call to discuss the project and your potential role. If accepted, we'll provide the CLA and get you started.
