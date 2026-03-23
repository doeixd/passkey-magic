# Release Guide

## Before Release

- run `npm test`
- run `npm run build`
- review `CHANGELOG.md`
- verify `README.md` examples still match the public API
- verify `SECURITY.md` still reflects current deployment guidance
- confirm package version in `package.json`

## Current Release Highlights

- grouped high-level APIs for passkeys, magic links, QR, and accounts
- persisted auth method metadata on sessions
- QR state machine hardening with desktop `statusToken`
- metadata support with end-to-end generic typing
- better-auth plugin and client integration, including metadata generics
- pluggable rate limiting with in-memory and unstorage-backed implementations
- production, security, and publishing documentation

## Production Readiness Checklist

- persistent storage configured
- shared rate limiter configured
- production email adapter configured
- HTTPS and exact WebAuthn origins configured
- secure cookie/session strategy configured in the host app
- staging environment tested with real passkeys and email delivery

## Publish Checklist

- update `CHANGELOG.md`
- bump version in `package.json`
- run `npm publish --access public` if appropriate for the package name
- create a git tag for the published version
- attach release notes using the relevant changelog section

## Recommended Post-Publish Checks

- install the published package in a clean sample app
- verify ESM imports work for:
  - `passkey-magic/server`
  - `passkey-magic/client`
  - `passkey-magic/adapters/memory`
  - `passkey-magic/adapters/unstorage`
  - `passkey-magic/better-auth`
  - `passkey-magic/better-auth/client`
- verify generated types resolve correctly in TypeScript
