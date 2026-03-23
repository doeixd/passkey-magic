# Improvement Plan

## Goals

- Make the library feel high-level and product-oriented without losing low-level WebAuthn correctness.
- Define the identity model explicitly so passkeys, magic links, and QR flows behave predictably.
- Strengthen QR login as a formal auth state machine instead of a loose set of helpers.
- Persist authentication method metadata so consumers can reason about session origin after login.

## Current Strengths

- The core primitives are already correct and flexible.
- The data model already allows passkey-only users because `email` is optional on `User`.
- The library already tracks auth method at the event/result layer.
- The client API already points toward a cleaner product surface with `registerPasskey()` and `signInWithPasskey()`.

## Main Design Issues

### 1. API shape is ceremony-first

The current server API exposes WebAuthn mechanics directly:

- `generateRegistrationOptions()`
- `verifyRegistration()`
- `generateAuthenticationOptions()`
- `verifyAuthentication()`

That is useful for advanced integrations, but it makes the public surface feel lower-level than the library's product promise. QR and magic link flows are already more task-oriented, so the passkey API should match that level of abstraction.

### 2. Identity rules are implicit

The implementation already supports multiple account entry points, but the library does not state the rules clearly enough:

- passkey registration can create a user without email
- magic link verification can create a user with email
- `linkEmail()` can attach email later
- magic link currently signs into an existing user if email matches, otherwise creates one

These are good defaults, but they should be treated as first-class design rules, not inferred behavior.

### 3. QR flow is only partially modeled as a state machine

QR sessions have states, but transition enforcement is split across different places. In particular, the high-level `completeQRSession()` flow updates QR session storage directly instead of routing completion through one central state machine.

That makes the design more fragile around:

- duplicate scans
- duplicate completion
- stale desktop tabs
- abandoned mobile flows
- expiry while scanned
- race conditions between polling and completion

### 4. Session origin is not persisted

Events expose `method`, but `Session` itself does not store how the session was created. After a session is validated later, consumers cannot reliably answer:

- was this session created by passkey?
- was it created by magic link?
- was it completed through QR?

That should be part of the persisted session record.

## Recommended Design Direction

## A. Adopt a two-layer API

Keep the low-level API for correctness and power users, but add a high-level API organized by user intent.

### High-level public shape

```ts
auth.passkeys.register.start(...)
auth.passkeys.register.finish(...)

auth.passkeys.signIn.start(...)
auth.passkeys.signIn.finish(...)

auth.magicLinks.send(...)
auth.magicLinks.verify(...)

auth.qr.create(...)
auth.qr.markScanned(...)
auth.qr.complete(...)
auth.qr.getStatus(...)
auth.qr.cancel(...)
```

Optional client-facing sugar can sit on top:

```ts
client.passkeys.register(...)
client.passkeys.signIn(...)
client.magicLinks.request(...)
client.qr.startDesktopLogin(...)
client.qr.completeOnMobile(...)
```

### Low-level compatibility layer

Retain the current methods, but position them as protocol-level primitives:

- `generateRegistrationOptions()`
- `verifyRegistration()`
- `generateAuthenticationOptions()`
- `verifyAuthentication()`

These can remain stable while the higher-level namespace becomes the recommended entry point in docs and examples.

## B. Make the identity model explicit

Document and enforce the following rules.

### Canonical account model

- A `User` is the canonical account entity.
- A user may exist with only passkeys, only email, or both.
- Email is optional globally, not required for all users.
- Authentication methods attach to a user; they are not separate account types.

### User creation rules

- Passkey registration may create a new user with no email.
- Magic link verification may create a new user with email.
- QR completion never creates a new identity by itself; it authenticates an already authenticated mobile user into a desktop flow.

### Linking rules

- `linkEmail(userId, email)` attaches email to an existing user.
- Adding a passkey to an authenticated user attaches a credential to that existing user.
- No implicit account merging during sign-in.

### Collision and merge policy

- If a magic link email already belongs to a user, sign into that user.
- If a passkey belongs to a user, sign into that user.
- If email is already linked to a different user, linking must fail.
- If account merging is ever introduced, it should be an explicit admin/user action, not an authentication side effect.

### Suggested documentation language

Include a short section in the README and API docs titled `Identity model` that answers:

- what a user is
- whether email is required
- which login methods can create a user
- which methods can attach to an existing user
- whether login can ever merge accounts automatically

## C. Formalize QR as a state machine

Treat QR login as a distributed authentication handshake with explicit states and transition guards.

### Proposed states

- `created`
- `scanned`
- `challenged`
- `authenticated`
- `expired`
- `cancelled`

If you want to stay lean, `challenged` can be deferred, but `cancelled` is still valuable.

### State meanings

- `created`: desktop initiated a QR login session
- `scanned`: mobile device scanned the QR code
- `challenged`: mobile device requested a passkey challenge and is mid-authentication
- `authenticated`: mobile device authenticated and desktop session is ready
- `expired`: time limit elapsed before success
- `cancelled`: the flow was intentionally invalidated by user or server

### Transition rules

- `created -> scanned`
- `scanned -> challenged`
- `challenged -> authenticated`
- `created|scanned|challenged -> expired`
- `created|scanned|challenged -> cancelled`

Disallow every other transition.

### Implementation guidance

- Route all QR transitions through `QRSessionManager`.
- Do not let top-level auth methods write QR session state directly.
- Make `completeQRSession()` call manager methods that validate state before mutation.
- Expiry checks should apply to `scanned` and `challenged` sessions too, not just initial state.
- Add idempotency behavior for duplicate scan/complete attempts where possible.

### Suggested record shape

```ts
interface QRSession {
  id: string
  state: 'created' | 'scanned' | 'challenged' | 'authenticated' | 'expired' | 'cancelled'
  initiatedAt: Date
  scannedAt?: Date
  challengedAt?: Date
  authenticatedAt?: Date
  expiresAt: Date
  desktopSessionToken?: string
  authenticatedUserId?: string
}
```

You may not need every timestamp immediately, but adding room for them will help debugging and analytics.

## D. Persist auth method on sessions

Extend `Session` so session origin survives past the initial response/event.

### Proposed shape

```ts
interface Session {
  id: string
  token: string
  userId: string
  authMethod: 'passkey' | 'magic-link' | 'qr'
  createdAt: Date
  expiresAt: Date
  userAgent?: string
  ipAddress?: string
  authContext?: {
    qrSessionId?: string
  }
}
```

### Benefits

- session validation can report how the user authenticated
- audit logs become simpler
- consumers can apply different policies based on auth origin
- analytics and support debugging become easier

## E. Clarify method semantics in hooks and events

The event system is already useful. Build on that by making the method semantics more explicit.

### Keep

- `session:created` with auth method
- `magic-link:sent`
- `qr:scanned`
- `qr:completed`

### Improve

- include persisted `session.authMethod` in downstream API results
- consider adding QR lifecycle events such as `qr:expired` and `qr:cancelled`
- consider adding richer hook context for linking and user creation decisions

## Recommended Implementation Order

### Phase 1: Identity and docs

- Write and publish the identity model.
- Update README examples to show:
  - passkey-only registration
  - linking email later
  - magic link sign-in behavior for existing users
- Add terminology guidance so users understand the difference between authentication method and account identity.

### Phase 2: Persist auth method

- Add `authMethod` to `Session`.
- Update session creation across passkey, magic link, and QR flows.
- Expose that metadata through validation and session listing APIs.

### Phase 3: QR state machine refactor

- Expand QR states and centralize transitions.
- Ensure expiry applies consistently across non-terminal states.
- Add tests for duplicate scan, duplicate completion, cancellation, and stale session polling.

### Phase 4: Higher-level API layer

- Add grouped namespaces for passkeys, magic links, and QR.
- Keep the existing low-level API as an advanced layer.
- Move docs and examples to recommend the grouped API first.

## Concrete API Proposal

```ts
const auth = createAuth(config)

await auth.passkeys.register.start({ userId, email })
await auth.passkeys.register.finish({ userId, response })

await auth.passkeys.signIn.start({ userId })
await auth.passkeys.signIn.finish({ response })

await auth.passkeys.add.start({ userId })
await auth.passkeys.add.finish({ userId, response })

await auth.magicLinks.send({ email })
await auth.magicLinks.verify({ token })

await auth.qr.create()
await auth.qr.markScanned({ sessionId })
await auth.qr.complete({ sessionId, response })
await auth.qr.getStatus({ sessionId })
await auth.qr.cancel({ sessionId })
```

Keep the existing methods available as aliases or advanced primitives during migration.

## Testing Priorities

Add or expand tests for the following:

- passkey registration creates a user without email
- linking email after passkey-only signup
- magic link signs into existing email-backed user
- no implicit account merge across conflicting identities
- QR expiry after scan but before completion
- duplicate QR scan behavior
- duplicate QR completion behavior
- session validation returns persisted auth method

## Launch Readiness Criteria

Before treating the library as stable, the following should be true:

- identity rules are documented explicitly
- session origin is persisted
- QR transitions are centralized and tested
- docs recommend the high-level API first
- low-level methods remain available for advanced integrations

## Short Version

If only a few changes can happen before launch, prioritize these:

1. Document the identity model.
2. Persist `authMethod` on `Session`.
3. Refactor QR into a real state machine with centralized transitions.
4. Add a grouped high-level API namespace and make it the documented default.
