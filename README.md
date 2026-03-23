# passkey-magic

Passkey-first authentication with QR cross-device login and magic link fallback.

- **Passkeys (WebAuthn)** — Register and sign in with biometrics, security keys, or platform authenticators
- **QR Cross-Device** — Scan a QR code on your phone to log in on desktop
- **Magic Links** — Email-based passwordless fallback
- **Framework Agnostic** — Works with any JavaScript runtime (Node.js, Bun, Deno, Cloudflare Workers)
- **better-auth Plugin** — Drop-in integration with [better-auth](https://github.com/better-auth/better-auth)

## Install

```bash
npm install passkey-magic
```

For production deployment guidance, see `SECURITY.md` and `RELEASE.md`.

## Quick Start

### Server

```ts
import { createAuth } from 'passkey-magic/server'
import { memoryAdapter } from 'passkey-magic/adapters/memory'

const auth = createAuth({
  rpName: 'My App',
  rpID: 'example.com',
  origin: 'https://example.com',
  storage: memoryAdapter(),
  rateLimit: {
    rules: {
      'magicLink.send': { limit: 5, windowMs: 15 * 60 * 1000 },
    },
  },
})

// Use as a Web Standard Request handler
export default {
  fetch: auth.createHandler({ pathPrefix: '/auth' })
}

// Grouped API is the recommended default
const { userId, options } = await auth.passkeys.register.start({
  email: 'user@example.com',
})
```

### Client

```ts
import { createClient } from 'passkey-magic/client'

const auth = createClient({
  request: (endpoint, body) =>
    fetch(`/auth${endpoint}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
    }).then(r => r.json()),
})

// Register a passkey
const { user, session } = await auth.passkeys.register({ email: 'user@example.com' })

// Sign in
const result = await auth.passkeys.signIn()
```

Client ergonomics helpers are also available:

```ts
import { AuthClientError, createClient } from 'passkey-magic/client'

const auth = createClient({ request })

try {
  await auth.accounts.get()
} catch (error) {
  if (error instanceof AuthClientError) {
    console.error(error.status, error.message)
  }
}

const session = await auth.waitForQRSession(sessionId, statusToken)
const token = auth.extractMagicLinkToken(window.location.href)
await auth.verifyMagicLinkURL({ url: window.location.href })
```

## Features

## Identity Model

`passkey-magic` treats `User` as the canonical account record.

- Passkey registration can create a user without an email.
- Magic link verification can create a user with an email.
- Email is optional overall and can be linked later with `linkEmail()`.
- Signing in never merges accounts implicitly.
- QR completion authenticates an existing mobile user into a desktop session; it does not create a new identity on its own.

That means the library supports three common shapes cleanly:

- passkey-only accounts
- email-only accounts created through magic links
- accounts that start with one method and attach the other later

If a magic link is verified for an email that already belongs to a user, the existing user is signed in. If an email is already linked to a different user, `linkEmail()` fails instead of merging accounts.

### Passkey Authentication

The grouped API is the recommended primary surface:

```ts
const { userId, options } = await auth.passkeys.register.start({
  email: 'user@example.com',
})

const result = await auth.passkeys.register.finish({
  userId,
  response: browserResponse,
})

const { options: signInOptions } = await auth.passkeys.signIn.start()
const signIn = await auth.passkeys.signIn.finish({ response: browserResponse })
```

The low-level WebAuthn methods are still available for advanced integrations:

```ts
const { options, userId } = await auth.generateRegistrationOptions({ email: 'user@example.com' })
const result = await auth.verifyRegistration({ userId, response: browserResponse })
```

### QR Cross-Device Login

QR login is modeled as a short-lived state machine. Sessions move through `created`, `scanned`, `challenged`, `authenticated`, `expired`, or `cancelled`.

Polling stops automatically once the session reaches `authenticated`, `expired`, or `cancelled`.

Security model:

- `sessionId` inside the QR code is a bearer capability for attempting mobile completion.
- `statusToken` is a separate desktop-only secret used for polling and cancellation.
- Possession of `sessionId` alone does not reveal desktop status, but it does allow a scanner to attempt authentication into that desktop flow.
- In other words, whoever scans the QR first can try to complete login on the desktop if they can also satisfy mobile authentication.

For stronger protection, you can enable an optional short confirmation code:

```ts
const auth = createAuth({
  // ...other config
  qrConfirmation: {
    enabled: true,
    codeLength: 6,
  },
})
```

This is acceptable for many QR login designs, but it is not equivalent to strong desktop/mobile device binding. If you need stronger protection against QR capture or confused-deputy style flow hijacking, add a desktop confirmation step or short approval code in your application UX.

```ts
// Desktop: create session and display QR code
const { sessionId, statusToken, confirmationCode } = await auth.qr.create()
const qrSvg = auth.qr.render(`https://example.com/auth/qr/${sessionId}`)

// Desktop: poll for completion
for await (const status of auth.qr.poll(sessionId, statusToken)) {
  if (status.state === 'authenticated') {
    // User logged in from their phone
  }
}

// Mobile: complete the session
await auth.qr.complete({ sessionId, confirmationCode })

// Optional: cancel an in-flight QR login
await auth.qr.cancel({ sessionId, statusToken })
```

Operational guidance:

- rate limit QR create, scan, and complete endpoints
- keep QR session TTLs short
- do not log `statusToken`
- treat the QR code itself as sensitive until scanned or expired

### Magic Links

Enable by providing an email adapter:

```ts
const auth = createAuth({
  // ...webauthn config
  storage: memoryAdapter(),
  email: {
    async sendMagicLink(email, url, token) {
      await sendEmail({ to: email, subject: 'Login', html: `<a href="${url}">Log in</a>` })
    }
  },
  magicLinkURL: 'https://example.com/auth/verify',
})

// Send a magic link
await auth.magicLinks.request({ email: 'user@example.com' })

// Verify (after user clicks the link)
const { user, session, isNewUser } = await auth.magicLinks.verify({ token })
```

### Passkey Management

```ts
// Add a passkey to an existing account
const { options } = await auth.passkeys.add.start({ userId })
const { credential } = await auth.passkeys.add.finish({ userId, response: browserResponse })

// List, update, remove
const credentials = await auth.passkeys.list(userId)
await auth.passkeys.update({ credentialId: 'cred_123', label: 'iPhone' })
await auth.passkeys.remove('cred_123')
```

Both users and passkeys can also carry JSON metadata.

```ts
await auth.accounts.updateMetadata({
  userId,
  metadata: { plan: 'pro', onboardingComplete: true },
})

await auth.passkeys.update({
  credentialId: 'cred_123',
  metadata: { nickname: 'Work MacBook', platform: 'macos' },
})
```

### Accounts And Identity

```ts
const user = await auth.accounts.get(userId)
const sameUser = await auth.accounts.getByEmail('user@example.com')

const canLink = await auth.accounts.canLinkEmail({
  userId,
  email: 'user@example.com',
})

if (canLink.ok) {
  await auth.accounts.linkEmail({ userId, email: 'user@example.com' })
}

await auth.accounts.unlinkEmail({ userId })
```

On the client, the same account workflow is available for the current authenticated user:

```ts
const profile = await auth.accounts.get()
const canLink = await auth.accounts.canLinkEmail('user@example.com')

if (canLink.ok) {
  await auth.accounts.linkEmail('user@example.com')
}
```

### Typed Metadata

You can thread metadata types through both server and client APIs.

```ts
type UserMeta = {
  theme: 'light' | 'dark'
}

type CredentialMeta = {
  nickname: string
}

const auth = createAuth<UserMeta, CredentialMeta>({
  rpName: 'My App',
  rpID: 'example.com',
  origin: 'https://example.com',
  storage: memoryAdapter<UserMeta, CredentialMeta>(),
})

await auth.accounts.updateMetadata({
  userId: 'user_123',
  metadata: { theme: 'dark' },
})

await auth.passkeys.update({
  credentialId: 'cred_123',
  metadata: { nickname: 'Work MacBook' },
})
```

The better-auth plugin also accepts the same metadata generics:

```ts
const plugin = passkeyMagicPlugin<UserMeta, CredentialMeta>({
  rpName: 'My App',
  rpID: 'example.com',
  origin: 'https://example.com',
})
```

### Session Management

```ts
const result = await auth.validateSession(token)  // { user, session } | null

if (result) {
  result.session.authMethod // 'passkey' | 'magic-link' | 'qr'
}

const sessions = await auth.getUserSessions(userId)
await auth.revokeSession(token)
await auth.revokeAllSessions(userId)
```

On the client, session validation uses the authenticated request transport directly:

```ts
const current = await auth.getSession()
```

### Rate Limiting

Sensitive public routes are rate-limited by default with an in-memory limiter.

For production, prefer a shared limiter implementation across instances.

```ts
import { createAuth, createMemoryRateLimiter, createUnstorageRateLimiter } from 'passkey-magic/server'
import { createStorage } from 'unstorage'

const auth = createAuth({
  // ...auth config
  rateLimit: {
    limiter: createMemoryRateLimiter(),
    rules: {
      'magicLink.send': { limit: 5, windowMs: 15 * 60 * 1000 },
      'email.available': null, // disable if you handle this elsewhere
    },
  },
})

const sharedLimiter = createUnstorageRateLimiter(createStorage())

const prodAuth = createAuth({
  // ...auth config
  rateLimit: {
    limiter: sharedLimiter,
  },
})
```

If you use the better-auth plugin, you can pass the same `rateLimit` config there too.

When used as a Better Auth plugin, `passkey-magic` also exposes Better Auth-native plugin `rateLimit` rules for sensitive plugin endpoints when you configure `rateLimit.rules`.

### better-auth Cookies And Deployment

The Better Auth integration creates real Better Auth sessions and writes cookies through Better Auth's cookie system. That means Better Auth cookie settings apply to this plugin too, including:

- cookie prefixes and custom cookie names
- secure cookie behavior
- cross-subdomain cookie settings
- Safari/ITP deployment constraints

Recommended setup:

- keep frontend and Better Auth endpoints on the same site when possible
- use a reverse proxy or a shared parent domain for Safari compatibility
- configure Better Auth `advanced.crossSubDomainCookies` only when needed
- use Better Auth secure cookie settings in production

Example:

```ts
import { betterAuth } from 'better-auth'
import { passkeyMagicPlugin } from 'passkey-magic/better-auth'
import { createUnstorageRateLimiter } from 'passkey-magic/server'
import { createStorage } from 'unstorage'

const auth = betterAuth({
  trustedOrigins: ['https://app.example.com'],
  advanced: {
    useSecureCookies: true,
    crossSubDomainCookies: {
      enabled: true,
      domain: 'example.com',
    },
  },
  plugins: [
    passkeyMagicPlugin({
      rpName: 'My App',
      rpID: 'example.com',
      origin: 'https://app.example.com',
      rateLimit: {
        limiter: createUnstorageRateLimiter(createStorage()),
        rules: {
          'magicLink.send': { limit: 5, windowMs: 15 * 60 * 1000 },
        },
      },
    }),
  ],
})
```

## Production Checklist

Before shipping this in production:

- use persistent storage, not `memoryAdapter()`
- use a shared rate limiter across instances
- configure a real email delivery provider
- run behind HTTPS only
- set exact `rpID` and `origin` values for your deployed domains
- harden cookies/sessions in the host app
- monitor auth failures, magic-link delivery, and rate-limit events
- decide whether `email-available` should be exposed publicly at all

## Publishing

- `CHANGELOG.md` tracks notable changes
- `SECURITY.md` documents reporting and deployment guidance
- `RELEASE.md` contains a release checklist
- `prepublishOnly` runs tests and build before publishing

### Lifecycle Hooks

```ts
const auth = createAuth({
  // ...config
  hooks: {
    async beforeRegister({ email }) {
      if (await isBlocked(email)) return false // abort
    },
    async afterAuthenticate({ user, session }) {
      await logLogin(user.id)
    },
  },
})
```

### Events

```ts
auth.on('session:created', ({ session, user, method }) => { /* ... */ })
auth.on('credential:created', ({ credential, user }) => { /* ... */ })
auth.on('user:created', ({ user }) => { /* ... */ })
```

## Storage Adapters

### Memory (development)

```ts
import { memoryAdapter } from 'passkey-magic/adapters/memory'

const storage = memoryAdapter()
```

### Unstorage (production)

Works with any [unstorage](https://unstorage.unjs.io) driver (Redis, Vercel KV, Cloudflare KV, filesystem, etc.):

```ts
import { unstorageAdapter } from 'passkey-magic/adapters/unstorage'
import { createStorage } from 'unstorage'
import redisDriver from 'unstorage/drivers/redis'

const storage = unstorageAdapter(
  createStorage({ driver: redisDriver({ url: 'redis://localhost:6379' }) }),
  { base: 'auth' }
)
```

### Custom Adapter

Implement the `StorageAdapter` interface for any database:

```ts
import type { StorageAdapter } from 'passkey-magic/server'

const myAdapter: StorageAdapter = {
  createUser(user) { /* ... */ },
  getUserById(id) { /* ... */ },
  // ... see StorageAdapter interface for all methods
}
```

## Integrations

### Nitro

```ts
import { passkeyMagic, useAuth } from 'passkey-magic/nitro'

export default defineNitroPlugin(() => {
  passkeyMagic({
    rpName: 'My App',
    rpID: 'example.com',
    origin: 'https://example.com',
    pathPrefix: '/auth',
  }).setup(nitroApp)
})

// In route handlers:
const auth = useAuth()
const session = await auth.validateSession(token)
```

### better-auth

Use passkey-magic as a [better-auth](https://www.better-auth.com) plugin. All data is stored in better-auth's database, and sessions are unified with better-auth's session system.

#### Server

```ts
import { betterAuth } from 'better-auth'
import { passkeyMagicPlugin } from 'passkey-magic/better-auth'

const auth = betterAuth({
  database: myAdapter,
  plugins: [
    passkeyMagicPlugin({
      rpName: 'My App',
      rpID: 'example.com',
      origin: 'https://example.com',
    }),
  ],
})
```

#### Client

```ts
import { createAuthClient } from 'better-auth/client'
import { passkeyMagicClientPlugin } from 'passkey-magic/better-auth/client'

const auth = createAuthClient({
  plugins: [passkeyMagicClientPlugin()],
})

// All endpoints are type-safe:
await auth.passkeyMagic.register.options({ email: 'user@example.com' })
await auth.passkeyMagic.qr.create()
```

#### Plugin Endpoints

All endpoints are prefixed with `/passkey-magic/`:

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/register/options` | POST | No | Generate passkey registration options |
| `/register/verify` | POST | No | Verify registration and create session |
| `/authenticate/options` | POST | No | Generate authentication options |
| `/authenticate/verify` | POST | No | Verify authentication and create session |
| `/add/options` | POST | Yes | Add passkey to existing account |
| `/add/verify` | POST | Yes | Verify added passkey |
| `/credentials` | GET | Yes | List user's passkeys |
| `/credentials/update` | POST | Yes | Update passkey label |
| `/credentials/remove` | POST | Yes | Remove a passkey |
| `/qr/create` | POST | No | Create QR login session |
| `/qr/status` | GET | No | Poll QR session status |
| `/qr/scanned` | POST | No | Mark QR session as scanned |
| `/qr/complete` | POST | No | Complete QR auth and create session |
| `/magic-link/send` | POST | No | Send magic link email |
| `/magic-link/verify` | POST | No | Verify magic link and create session |

The plugin creates 4 database tables (`passkeyCredential`, `qrSession`, `passkeyChallenge`, `magicLinkToken`) and manages them through better-auth's adapter. Authentication endpoints create proper better-auth sessions with cookies.

## Configuration

```ts
interface AuthConfig {
  rpName: string              // Relying party name (shown in passkey prompts)
  rpID: string                // Relying party ID (your domain)
  origin: string | string[]   // Expected origin(s) for WebAuthn
  storage: StorageAdapter     // Persistence layer
  email?: EmailAdapter        // Enables magic links
  magicLinkURL?: string       // Base URL for magic link emails
  sessionTTL?: number         // Default: 7 days (ms)
  challengeTTL?: number       // Default: 60 seconds (ms)
  magicLinkTTL?: number       // Default: 15 minutes (ms)
  qrSessionTTL?: number       // Default: 5 minutes (ms)
  generateId?: () => string   // Default: crypto.randomUUID()
  hooks?: AuthHooks           // Lifecycle hooks
}
```

## License

MIT
