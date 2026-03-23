# Security Policy

## Supported Versions

This project is pre-`1.0.0`.

- The latest commit on the default branch is the only supported version.
- Older unpublished snapshots should be treated as unsupported.

## Reporting a Vulnerability

Please do not open public issues for security vulnerabilities.

Instead:
- contact the maintainer privately through the repository security reporting flow if enabled
- or send a private disclosure with reproduction steps, impact, and any proof-of-concept details

Include:
- affected version or commit
- runtime and deployment details
- storage adapter used
- whether better-auth integration is involved
- minimal reproduction steps

## Response Expectations

- Initial triage: best effort
- Fix timeline: depends on impact and exploitability
- Public disclosure: after a fix or mitigation is available

## Deployment Guidance

For production deployments:
- use a persistent storage backend, not `memoryAdapter()`
- use a shared rate limiter across instances
- prefer `createUnstorageRateLimiter()` or a custom atomic limiter
- use HTTPS only and configure `rpID` and `origin` exactly
- use secure, HTTP-only session cookies in the host app
- monitor magic link delivery, auth failures, and rate-limit events

## Known Security Tradeoffs

- `email-available` can enable account enumeration if exposed publicly
- the built-in unstorage rate limiter is shared but not strictly atomic under high contention
- for strict abuse resistance, use a stronger shared limiter implementation
