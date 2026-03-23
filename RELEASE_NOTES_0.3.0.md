# passkey-magic 0.3.0

This release builds on `0.2.0` with stronger QR login protection and significantly better frontend ergonomics.

## Highlights

- Added an optional QR confirmation-code flow for stronger desktop/mobile confirmation.
- Added more explicit QR threat-model documentation and additional QR route throttling.
- Added client-side UX helpers for QR flows, magic-link callback handling, session observation, and sign-in strategy selection.
- Added abort-signal support across the client transport and most client methods.
- Added focused additive Better Auth QR submodule exports for apps that only need the QR gap layer.

## Notable Changes

- QR login can now require a short confirmation code before mobile completion succeeds.
- `client.qr.createFlow(...)` returns a more ergonomic QR flow object for frontend apps.
- `client.waitForQRSession(...)`, `client.observeSession(...)`, and `client.getBestSignInMethod(...)` reduce common application glue code.
- `AuthClientError` now normalizes transport errors into a more useful client-facing shape.
- Magic-link tokens and QR bearer secrets are now hashed at rest.

## Upgrade Notes

- If you enable `qrConfirmation`, update your mobile completion UI to confirm the returned `confirmationCode`.
- Client request adapters should now accept an optional third argument: `{ signal?: AbortSignal }`.
- Existing simple client calls remain supported without passing options.

## Verification

- `npx vitest run --maxWorkers=1`
- `npm run build`
