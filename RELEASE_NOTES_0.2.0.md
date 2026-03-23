# passkey-magic 0.2.0

This release hardens the library for production use and significantly improves the public API.

## Highlights

- Added grouped high-level APIs for passkeys, QR login, magic links, and accounts.
- Added typed metadata support for users and credentials, including end-to-end generic typing across core APIs and better-auth integration.
- Hardened security around passkey registration, challenge binding, QR polling, account mutation authorization, and input validation.
- Added pluggable rate limiting with in-memory and shared unstorage-backed limiters.
- Improved better-auth integration with native plugin rate-limit rules and clearer cookie/deployment guidance.
- Added production, security, release, and publishing documentation.

## Notable Changes

- Sessions now persist `authMethod` and optional `authContext`.
- QR login now uses a stronger state machine and a desktop-held `statusToken` for polling/cancellation.
- Metadata can now be typed across `createAuth`, `createClient`, adapters, and better-auth plugin/client usage.
- Public docs now recommend the grouped high-level API first.

## Upgrade Notes

- If you use QR polling, update callers to pass the returned `statusToken`.
- If you rely on old low-level flows, they still exist, but grouped APIs are now the recommended default.
- For production multi-instance deployments, use a shared rate limiter instead of the in-memory default.

## Verification

- `npm test`
- `npm run build`
