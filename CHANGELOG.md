# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and the project aims to follow Semantic Versioning once it reaches `1.0.0`.

## [Unreleased]

## [0.4.0] - 2026-03-23

### Added
- Optional QR confirmation-code flow for stronger cross-device login confirmation.
- Additional QR security guidance and throttling for scan, confirm, and complete routes.
- Client-side UX helpers including `AuthClientError`, QR flow helpers, session observation, passkey sign-in strategy selection, and magic-link URL helpers.
- End-to-end abort-signal support across the client transport and most client methods.
- Focused additive Better Auth QR submodule exports: `passkey-magic/better-auth/qr` and `passkey-magic/better-auth/qr/client`.

### Changed
- Client APIs are more ergonomic with optional options objects for cancellation and control.
- QR client polling now supports backoff and jitter controls.

### Fixed
- Magic-link bearer tokens, QR `statusToken` values, and QR confirmation codes are now hashed at rest.

## [0.2.0] - 2026-03-23

### Added
- Grouped server and client APIs for passkeys, QR, magic links, and accounts.
- Typed metadata support for users and credentials, including end-to-end metadata generics.
- better-auth plugin and client metadata generics.
- QR desktop `statusToken` protection for polling and cancellation.
- Pluggable rate limiting with built-in memory and unstorage-backed limiters.
- Production-oriented docs for security, deployment, and publishing.

### Changed
- Sessions now persist `authMethod` and optional `authContext`.
- QR flow is modeled as an explicit state machine with stronger transition checks.
- Client/server route compatibility was tightened for account and session mutations.
- Public docs now prefer the grouped high-level API.

### Fixed
- Prevented cross-account session and credential mutations.
- Prevented unauthenticated passkey registration against existing user IDs.
- Bound passkey authentication challenges to requested user context.
- Added input length validation for token-like values, labels, and emails.

## [0.1.0] - 2026-03-23

### Added
- Initial passkey-first authentication library with WebAuthn, QR login, magic links, adapters, and better-auth integration.
