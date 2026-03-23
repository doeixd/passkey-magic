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
})

// Use as a Web Standard Request handler
export default {
  fetch: auth.createHandler({ pathPrefix: '/auth' })
}
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
const { user, session } = await auth.registerPasskey({ email: 'user@example.com' })

// Sign in
const result = await auth.signInWithPasskey()
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

```ts
// Server: generate options, verify response
const { options, userId } = await auth.generateRegistrationOptions({ email: 'user@example.com' })
const result = await auth.verifyRegistration({ userId, response: browserResponse })

// Authentication
const { options } = await auth.generateAuthenticationOptions()
const { user, session } = await auth.verifyAuthentication({ response: browserResponse })
```

### QR Cross-Device Login

QR login is modeled as a short-lived state machine. Sessions move through `created`, `scanned`, `challenged`, `authenticated`, `expired`, or `cancelled`.

Polling stops automatically once the session reaches `authenticated`, `expired`, or `cancelled`.

```ts
// Desktop: create session and display QR code
const { sessionId } = await auth.createQRSession()
const qrSvg = client.renderQR(`https://example.com/auth/qr/${sessionId}`)

// Desktop: poll for completion
for await (const status of client.pollQRSession(sessionId)) {
  if (status.state === 'authenticated') {
    // User logged in from their phone
  }
}

// Mobile: complete the session
await client.completeQRSession({ sessionId })

// Optional: cancel an in-flight QR login
await client.cancelQRSession(sessionId)
```

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
await auth.sendMagicLink({ email: 'user@example.com' })

// Verify (after user clicks the link)
const { user, session, isNewUser } = await auth.verifyMagicLink({ token })
```

### Passkey Management

```ts
// Add a passkey to an existing account
const { options } = await auth.addPasskey({ userId })
const { credential } = await auth.verifyAddPasskey({ userId, response: browserResponse })

// List, update, remove
const credentials = await auth.getUserCredentials(userId)
await auth.updateCredential({ credentialId: 'cred_123', label: 'iPhone' })
await auth.removeCredential('cred_123')
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
