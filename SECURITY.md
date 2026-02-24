# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Aegis SDK, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

### How to report

Email: **security@aegis-sdk.dev**

Include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment (what an attacker could achieve)
- Suggested fix (if you have one)

### What to expect

- **Acknowledgment** within 48 hours
- **Initial assessment** within 5 business days
- **Fix timeline** communicated within 10 business days
- **Credit** in the release notes (unless you prefer anonymity)

### Scope

The following are in scope for security reports:

| In Scope | Out of Scope |
|----------|-------------|
| Bypass of input scanner detection | Known false negatives documented in tests/adversarial/ |
| Bypass of stream monitor detection | Detection rate on novel attack techniques not yet in the threat model |
| Bypass of action validator policy enforcement | Configuration errors in user-supplied policies |
| Information leakage through audit logs | Vulnerabilities in user-supplied LLM providers |
| Type system escape from Quarantined<T> | Issues in dependencies (report to those projects directly) |
| Sandbox escape (structured output bypass) | Performance issues that aren't denial-of-service |

### Detection Bypasses vs. Vulnerabilities

Aegis is a defense-in-depth library. No single layer is expected to catch 100% of attacks. A bypass of one detection layer is a valuable finding, but it's a **detection gap**, not necessarily a **security vulnerability** in Aegis itself.

- **Detection gaps**: Novel attack patterns that evade the scanner or monitor. These are valuable contributions. Consider submitting them through [The Aegis Protocol](https://github.com/aegis-sdk/Aegis/blob/main/HALL_OF_FAME.md) for public recognition.
- **Security vulnerabilities**: Flaws in Aegis's own code that compromise the security guarantees it promises (e.g., type system escapes, audit log tampering, policy enforcement bypass).

### Supported Versions

| Version | Supported |
|---------|-----------|
| Latest release | Yes |
| Previous minor | Best effort |
| < 0.3.0 | No |

## Security Best Practices

When using Aegis in production:

1. Always use defense-in-depth — don't rely on a single layer
2. Keep Aegis updated to get the latest detection patterns
3. Monitor audit logs for attack patterns
4. Configure alerting for rate spikes and session kills
5. Use the strictest policy that works for your use case
6. Test with the red team tools (`@aegis-sdk/testing`) before deploying
7. Set up canary tokens in your system prompts
8. Enable PII detection for any user-facing application
9. Use the Sandbox for processing untrusted content (emails, documents)
10. Review the [production deployment guide](https://aegis-sdk.github.io/Aegis/guide/production) before going live
