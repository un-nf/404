# Security Policy

## Reporting Security Issues

**Do not open public issues for security vulnerabilities.**

If you discover a security issue in 404, email us directly:

**404mesh@proton.me**

Include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment (what can an attacker do?)
- Affected versions/components
- Any proof-of-concept code (if applicable)

We'll respond within 72 hours. If the issue is valid, we'll work with you on disclosure timing and credit.

## Scope

Security issues we care about:

### Critical
- CA certificate leakage or mishandling (handled by mitmproxy if using https://mitm.it)
- CSP breakage or XSS pathway openings
- Plaintext credential exposure beyond intended localhost MITM scope
- Remote code execution
- Privilege escalation
- Authentication bypass in proxy configuration
- Memory corruption that leads to code execution

### High Priority
- Header injection vulnerabilities
- CSP bypass that weakens site security
- JavaScript injection outside intended spoofing scope
- Profile data leakage between sessions
- Cryptographic implementation flaws

### Medium Priority
- Information disclosure (fingerprint config, metadata)
- Denial of service (local only)
- Logic errors in fingerprint spoofing that break anonymity
- Session handling bugs

### Out of Scope
- Issues requiring physical access to the user's machine
- Social engineering attacks
- Third-party mitmproxy vulnerabilities (report to mitmproxy project)
- Browser bugs unrelated to 404's modifications
- Theoretical attacks without proof of concept

## Known Risks

- 404 is a TLS-terminating MITM proxy.
- 
### Inherent Risks
- **Plaintext exposure**: The proxy can see passwords, tokens, and session data. Do not use primary accounts.
- **CA certificate**: If your mitmproxy CA cert is compromised, an attacker can MITM your traffic. Never share it.
- **Local access**: If your machine is compromised, the proxy's data and certificates are accessible. Standard threat model applies.

### What We Don't Do
- Log credentials or session tokens (but the proxy *can* see them)
- Phone home or transmit data
- Store behavioral profiles persistently (outside in-memory session data)
- Route traffic through external infrastructure

Read the code. Verify these claims yourself.

## Security Best Practices

If you're running 404:

1. **Never share your CA certificate**. Not with anyone, not for any reason.
2. **Use disposable accounts** for testing login flows.
3. **Run in an isolated environment** if possible (VM, separate user account).
4. **Keep mitmproxy updated**. We depend on their security.
5. **Audit the code** before running it. This is a MITM proxy.
6. **Monitor your CA cert store**. Make sure only your mitmproxy cert is installed.

## Development Security

If you're contributing to 404:

- Sign your commits (GPG)
- Never commit secrets, test credentials, or CA certificates
- Test changes in isolated environments
- Document security implications of new features
- Run static analysis and linters
- Review dependencies for known vulnerabilities

## Disclosure Policy

We follow coordinated disclosure:

1. You report the issue privately
2. We acknowledge and validate
3. We develop and test a fix
4. We agree on disclosure timeline (typically 90 days max)
5. We release the patch
6. We publish a security advisory
7. You get credit (if desired)

If you need to disclose publicly before we've patched, give us at least 7 days notice.

## Contact

**Email:** 404mesh@proton.me

**PGP:** (not yet available)

**Response time:** 72 hours for initial acknowledgment

Do not use Discord, GitHub issues, or social media for security reports.
