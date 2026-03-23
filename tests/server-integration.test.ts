import { describe, it, expect, vi, beforeEach } from 'vitest'
import { createAuth } from '../src/server/index.js'
import { memoryAdapter } from '../src/adapters/memory.js'
import type { EmailAdapter, StorageAdapter } from '../src/types.js'

describe('createAuth', () => {
  let storage: StorageAdapter

  beforeEach(() => {
    storage = memoryAdapter()
  })

  function makeAuth(overrides?: Record<string, unknown>) {
    return createAuth({
      rpName: 'Test App',
      rpID: 'localhost',
      origin: 'http://localhost:3000',
      storage,
      ...overrides,
    })
  }

  // ── API Surface ──

  describe('API surface without email', () => {
    it('has passkey methods', () => {
      const auth = makeAuth()
      expect(auth.generateRegistrationOptions).toBeTypeOf('function')
      expect(auth.verifyRegistration).toBeTypeOf('function')
      expect(auth.generateAuthenticationOptions).toBeTypeOf('function')
      expect(auth.verifyAuthentication).toBeTypeOf('function')
    })

    it('has passkey management methods', () => {
      const auth = makeAuth()
      expect(auth.addPasskey).toBeTypeOf('function')
      expect(auth.verifyAddPasskey).toBeTypeOf('function')
      expect(auth.updateCredential).toBeTypeOf('function')
      expect(auth.removeCredential).toBeTypeOf('function')
      expect(auth.getUserCredentials).toBeTypeOf('function')
    })

    it('has QR methods', () => {
      const auth = makeAuth()
      expect(auth.createQRSession).toBeTypeOf('function')
      expect(auth.getQRSessionStatus).toBeTypeOf('function')
      expect(auth.markQRSessionScanned).toBeTypeOf('function')
      expect(auth.completeQRSession).toBeTypeOf('function')
    })

    it('has session management methods', () => {
      const auth = makeAuth()
      expect(auth.validateSession).toBeTypeOf('function')
      expect(auth.getUserSessions).toBeTypeOf('function')
      expect(auth.revokeSession).toBeTypeOf('function')
      expect(auth.revokeSessionById).toBeTypeOf('function')
      expect(auth.revokeAllSessions).toBeTypeOf('function')
    })

    it('has account management methods', () => {
      const auth = makeAuth()
      expect(auth.getUser).toBeTypeOf('function')
      expect(auth.isEmailAvailable).toBeTypeOf('function')
      expect(auth.linkEmail).toBeTypeOf('function')
      expect(auth.unlinkEmail).toBeTypeOf('function')
      expect(auth.deleteAccount).toBeTypeOf('function')
    })

    it('has event system', () => {
      const auth = makeAuth()
      expect(auth.on).toBeTypeOf('function')
    })

    it('does NOT have magic link methods', () => {
      const auth = makeAuth()
      expect((auth as any).sendMagicLink).toBeUndefined()
      expect((auth as any).verifyMagicLink).toBeUndefined()
    })
  })

  describe('API surface with email', () => {
    it('has magic link methods', () => {
      const auth = makeAuth({
        email: { sendMagicLink: vi.fn(async () => {}) },
        magicLinkURL: 'http://localhost:3000/auth/verify',
      })
      expect(auth.sendMagicLink).toBeTypeOf('function')
      expect(auth.verifyMagicLink).toBeTypeOf('function')
    })
  })

  // ── Hooks ──

  describe('hooks', () => {
    it('blocks registration when hook returns false', async () => {
      const auth = makeAuth({ hooks: { beforeRegister: async () => false } })
      await expect(
        auth.generateRegistrationOptions({ email: 'test@example.com' }),
      ).rejects.toThrow('Registration blocked by hook')
    })

    it('blocks authentication when hook returns false', async () => {
      const auth = makeAuth({ hooks: { beforeAuthenticate: async () => false } })
      await expect(auth.generateAuthenticationOptions()).rejects.toThrow('Authentication blocked by hook')
    })

    it('blocks magic link when hook returns false', async () => {
      const auth = makeAuth({
        email: { sendMagicLink: vi.fn(async () => {}) },
        magicLinkURL: 'http://localhost:3000/auth/verify',
        hooks: { beforeMagicLink: async () => false },
      })
      await expect(
        auth.sendMagicLink({ email: 'test@example.com' }),
      ).rejects.toThrow('Magic link blocked by hook')
    })
  })

  // ── Events ──

  describe('events', () => {
    it('emits qr:scanned', async () => {
      const auth = makeAuth()
      const handler = vi.fn()
      auth.on('qr:scanned', handler)

      const { sessionId } = await auth.createQRSession()
      await auth.markQRSessionScanned(sessionId)
      expect(handler).toHaveBeenCalledWith({ sessionId })
    })
  })

  // ── Magic Link Flow ──

  describe('magic link full flow', () => {
    it('sends and verifies, creating new user with events', async () => {
      const sentEmails: { email: string; url: string; token: string }[] = []
      const auth = makeAuth({
        email: {
          sendMagicLink: vi.fn(async (email: string, url: string, token: string) => {
            sentEmails.push({ email, url, token })
          }),
        } as EmailAdapter,
        magicLinkURL: 'http://localhost:3000/auth/verify',
      })

      const userCreated = vi.fn()
      const sessionCreated = vi.fn()
      auth.on('user:created', userCreated)
      auth.on('session:created', sessionCreated)

      await auth.sendMagicLink({ email: 'new@example.com' })
      expect(sentEmails).toHaveLength(1)

      const result = await auth.verifyMagicLink({ token: sentEmails[0].token })
      expect(result.method).toBe('magic-link')
      expect(result.isNewUser).toBe(true)
      expect(result.user.email).toBe('new@example.com')
      expect(result.session.token).toBeTruthy()
      expect(result.session.authMethod).toBe('magic-link')
      expect(userCreated).toHaveBeenCalledOnce()
      expect(sessionCreated).toHaveBeenCalledWith(expect.objectContaining({ method: 'magic-link' }))
    })

    it('rejects invalid email format', async () => {
      const auth = makeAuth({
        email: { sendMagicLink: vi.fn(async () => {}) } as EmailAdapter,
        magicLinkURL: 'http://localhost:3000/auth/verify',
      })
      await expect(auth.sendMagicLink({ email: 'not-an-email' })).rejects.toThrow('Invalid email')
    })
  })

  // ── Email Management ──

  describe('email management', () => {
    it('links email to user', async () => {
      const auth = makeAuth()
      await storage.createUser({ id: 'u1', createdAt: new Date() })

      const { user } = await auth.linkEmail({ userId: 'u1', email: 'a@b.com' })
      expect(user.email).toBe('a@b.com')

      const fetched = await auth.getUser('u1')
      expect(fetched?.email).toBe('a@b.com')
    })

    it('rejects invalid email format on linkEmail', async () => {
      const auth = makeAuth()
      await storage.createUser({ id: 'u1', createdAt: new Date() })
      await expect(auth.linkEmail({ userId: 'u1', email: 'bad' })).rejects.toThrow('Invalid email')
    })

    it('rejects linking email already used by another user', async () => {
      const auth = makeAuth()
      await storage.createUser({ id: 'u1', email: 'taken@example.com', createdAt: new Date() })
      await storage.createUser({ id: 'u2', createdAt: new Date() })

      await expect(
        auth.linkEmail({ userId: 'u2', email: 'taken@example.com' }),
      ).rejects.toThrow('already linked')
    })

    it('allows re-linking the same email to the same user', async () => {
      const auth = makeAuth()
      await storage.createUser({ id: 'u1', email: 'same@example.com', createdAt: new Date() })

      const { user } = await auth.linkEmail({ userId: 'u1', email: 'same@example.com' })
      expect(user.email).toBe('same@example.com')
    })

    it('emits email:linked event', async () => {
      const auth = makeAuth()
      await storage.createUser({ id: 'u1', createdAt: new Date() })
      const handler = vi.fn()
      auth.on('email:linked', handler)

      await auth.linkEmail({ userId: 'u1', email: 'a@b.com' })
      expect(handler).toHaveBeenCalledWith({ userId: 'u1', email: 'a@b.com' })
    })

    it('checks email availability', async () => {
      const auth = makeAuth()
      expect(await auth.isEmailAvailable('free@example.com')).toBe(true)

      await storage.createUser({ id: 'u1', email: 'taken@example.com', createdAt: new Date() })
      expect(await auth.isEmailAvailable('taken@example.com')).toBe(false)
    })

    it('returns false for invalid email format in isEmailAvailable', async () => {
      const auth = makeAuth()
      expect(await auth.isEmailAvailable('not-valid')).toBe(false)
    })

    it('unlinks email', async () => {
      const auth = makeAuth()
      await storage.createUser({ id: 'u1', email: 'a@b.com', createdAt: new Date() })
      await storage.createCredential({
        id: 'c1', userId: 'u1', publicKey: new Uint8Array([1]),
        counter: 0, deviceType: 'singleDevice', backedUp: false, createdAt: new Date(),
      })

      const handler = vi.fn()
      auth.on('email:unlinked', handler)

      const { user } = await auth.unlinkEmail({ userId: 'u1' })
      expect(user.email).toBeUndefined()
      expect(handler).toHaveBeenCalledWith({ userId: 'u1', email: 'a@b.com' })
    })

    it('prevents unlinking email when user has no passkeys', async () => {
      const auth = makeAuth()
      await storage.createUser({ id: 'u1', email: 'a@b.com', createdAt: new Date() })

      await expect(auth.unlinkEmail({ userId: 'u1' })).rejects.toThrow('no passkeys')
    })

    it('throws when unlinking email from user with no email', async () => {
      const auth = makeAuth()
      await storage.createUser({ id: 'u1', createdAt: new Date() })
      await expect(auth.unlinkEmail({ userId: 'u1' })).rejects.toThrow('no email')
    })
  })

  // ── Credential Management ──

  describe('credential management', () => {
    it('updates credential label', async () => {
      const auth = makeAuth()
      await storage.createUser({ id: 'u1', createdAt: new Date() })
      await storage.createCredential({
        id: 'c1', userId: 'u1', publicKey: new Uint8Array([1]),
        counter: 0, deviceType: 'singleDevice', backedUp: false, createdAt: new Date(),
      })

      const handler = vi.fn()
      auth.on('credential:updated', handler)

      await auth.updateCredential({ credentialId: 'c1', label: 'My iPhone' })
      expect(handler).toHaveBeenCalledWith({ credentialId: 'c1', userId: 'u1' })
    })

    it('throws when updating nonexistent credential', async () => {
      const auth = makeAuth()
      await expect(
        auth.updateCredential({ credentialId: 'nope', label: 'x' }),
      ).rejects.toThrow('not found')
    })

    it('removes credential', async () => {
      const auth = makeAuth()
      await storage.createUser({ id: 'u1', email: 'a@b.com', createdAt: new Date() })
      await storage.createCredential({
        id: 'c1', userId: 'u1', publicKey: new Uint8Array([1]),
        counter: 0, deviceType: 'singleDevice', backedUp: false, createdAt: new Date(),
      })
      await storage.createCredential({
        id: 'c2', userId: 'u1', publicKey: new Uint8Array([2]),
        counter: 0, deviceType: 'singleDevice', backedUp: false, createdAt: new Date(),
      })

      const handler = vi.fn()
      auth.on('credential:removed', handler)

      await auth.removeCredential('c1')
      expect(handler).toHaveBeenCalledWith({ credentialId: 'c1', userId: 'u1' })
      expect(await auth.getUserCredentials('u1')).toHaveLength(1)
    })

    it('prevents removing last passkey when user has no email', async () => {
      const auth = makeAuth()
      await storage.createUser({ id: 'u1', createdAt: new Date() })
      await storage.createCredential({
        id: 'c1', userId: 'u1', publicKey: new Uint8Array([1]),
        counter: 0, deviceType: 'singleDevice', backedUp: false, createdAt: new Date(),
      })

      await expect(auth.removeCredential('c1')).rejects.toThrow('Cannot remove the last passkey')
    })

    it('allows removing last passkey when user has email', async () => {
      const auth = makeAuth()
      await storage.createUser({ id: 'u1', email: 'a@b.com', createdAt: new Date() })
      await storage.createCredential({
        id: 'c1', userId: 'u1', publicKey: new Uint8Array([1]),
        counter: 0, deviceType: 'singleDevice', backedUp: false, createdAt: new Date(),
      })

      await auth.removeCredential('c1')
      expect(await auth.getUserCredentials('u1')).toHaveLength(0)
    })

    it('throws when removing nonexistent credential', async () => {
      const auth = makeAuth()
      await expect(auth.removeCredential('nope')).rejects.toThrow('not found')
    })
  })

  // ── Session Management ──

  describe('session management', () => {
    it('lists user sessions', async () => {
      const auth = makeAuth()
      await storage.createUser({ id: 'u1', createdAt: new Date() })
      await storage.createSession({
        id: 's1', token: 't1', userId: 'u1',
        authMethod: 'passkey',
        expiresAt: new Date(Date.now() + 10000), createdAt: new Date(),
      })
      await storage.createSession({
        id: 's2', token: 't2', userId: 'u1',
        authMethod: 'magic-link',
        expiresAt: new Date(Date.now() + 10000), createdAt: new Date(),
      })

      const sessions = await auth.getUserSessions('u1')
      expect(sessions).toHaveLength(2)
    })

    it('revokes session by ID', async () => {
      const auth = makeAuth()
      await storage.createSession({
        id: 's1', token: 't1', userId: 'u1',
        authMethod: 'passkey',
        expiresAt: new Date(Date.now() + 10000), createdAt: new Date(),
      })

      await auth.revokeSessionById('s1')
      expect(await auth.validateSession('t1')).toBeNull()
    })
  })

  // ── Delete Account ──

  describe('deleteAccount', () => {
    it('deletes user, credentials, and sessions', async () => {
      const auth = makeAuth()
      await storage.createUser({ id: 'u1', email: 'a@b.com', createdAt: new Date() })
      await storage.createCredential({
        id: 'c1', userId: 'u1', publicKey: new Uint8Array([1]),
        counter: 0, deviceType: 'singleDevice', backedUp: false, createdAt: new Date(),
      })
      await storage.createSession({
        id: 's1', token: 't1', userId: 'u1',
        authMethod: 'passkey',
        expiresAt: new Date(Date.now() + 10000), createdAt: new Date(),
      })

      const handler = vi.fn()
      auth.on('user:deleted', handler)

      await auth.deleteAccount('u1')

      expect(await auth.getUser('u1')).toBeNull()
      expect(await auth.getUserCredentials('u1')).toHaveLength(0)
      expect(await auth.validateSession('t1')).toBeNull()
      expect(handler).toHaveBeenCalledWith({ userId: 'u1' })
    })
  })

  // ── Add Passkey ──

  describe('addPasskey', () => {
    it('throws if user does not exist', async () => {
      const auth = makeAuth()
      await expect(auth.addPasskey({ userId: 'nope' })).rejects.toThrow('User not found')
    })

    it('generates options for existing user', async () => {
      const auth = makeAuth()
      await storage.createUser({ id: 'u1', email: 'a@b.com', createdAt: new Date() })

      const { options } = await auth.addPasskey({ userId: 'u1' })
      expect(options.rp).toBeDefined()
      expect(options.challenge).toBeTruthy()
    })

    it('excludes existing credentials', async () => {
      const auth = makeAuth()
      await storage.createUser({ id: 'u1', createdAt: new Date() })
      await storage.createCredential({
        id: 'existing', userId: 'u1', publicKey: new Uint8Array([1]),
        counter: 0, deviceType: 'singleDevice', backedUp: false, createdAt: new Date(),
      })

      const { options } = await auth.addPasskey({ userId: 'u1' })
      expect(options.excludeCredentials).toHaveLength(1)
      expect(options.excludeCredentials![0].id).toBe('existing')
    })
  })

  // ── Handler ──

  describe('handler', () => {
    it('creates a handler', () => {
      const auth = makeAuth()
      const handler = auth.createHandler({ pathPrefix: '/api/auth' })
      expect(handler).toBeTypeOf('function')
    })

    it('returns 404 for unknown routes', async () => {
      const auth = makeAuth()
      const handler = auth.createHandler()
      const res = await handler(new Request('http://localhost/auth/unknown'))
      expect(res.status).toBe(404)
    })

    it('returns 401 for session without token', async () => {
      const auth = makeAuth()
      const handler = auth.createHandler()
      const res = await handler(new Request('http://localhost/auth/session'))
      expect(res.status).toBe(401)
    })

    it('returns 400 for invalid JSON body', async () => {
      const auth = makeAuth()
      const handler = auth.createHandler()
      const res = await handler(new Request('http://localhost/auth/passkey/register/options', {
        method: 'POST',
        body: 'not-json',
        headers: { 'Content-Type': 'application/json' },
      }))
      expect(res.status).toBe(400)
      const body = await res.json()
      expect(body.error).toContain('Invalid JSON')
    })

    it('handles QR session lifecycle', async () => {
      const auth = makeAuth()
      const handler = auth.createHandler()

      // Create
      const createRes = await handler(new Request('http://localhost/auth/qr/create', { method: 'POST' }))
      expect(createRes.status).toBe(200)
      const { sessionId } = await createRes.json()

      // Poll
      const statusRes = await handler(new Request(`http://localhost/auth/qr/${sessionId}/status`))
      expect(statusRes.status).toBe(200)
      expect((await statusRes.json()).state).toBe('created')

      // Scan
      const scanRes = await handler(new Request(`http://localhost/auth/qr/${sessionId}/scanned`, { method: 'POST' }))
      expect(scanRes.status).toBe(200)

      // Cancel
      const cancelRes = await handler(new Request(`http://localhost/auth/qr/${sessionId}/cancel`, { method: 'POST' }))
      expect(cancelRes.status).toBe(200)
    })

    it('returns 400 for magic link when not configured', async () => {
      const auth = makeAuth()
      const handler = auth.createHandler()
      const res = await handler(new Request('http://localhost/auth/magic-link/send', {
        method: 'POST',
        body: JSON.stringify({ email: 'a@b.com' }),
        headers: { 'Content-Type': 'application/json' },
      }))
      expect(res.status).toBe(400)
      expect((await res.json()).error).toBe('Magic link not configured')
    })

    it('handles email availability check', async () => {
      const auth = makeAuth()
      const handler = auth.createHandler()
      const res = await handler(new Request('http://localhost/auth/account/email-available', {
        method: 'POST',
        body: JSON.stringify({ email: 'free@example.com' }),
        headers: { 'Content-Type': 'application/json' },
      }))
      expect(res.status).toBe(200)
      expect((await res.json()).available).toBe(true)
    })

    it('requires auth for account routes', async () => {
      const auth = makeAuth()
      const handler = auth.createHandler()

      const routes = [
        ['GET', '/auth/account'],
        ['DELETE', '/auth/account'],
        ['GET', '/auth/account/sessions'],
        ['DELETE', '/auth/account/sessions'],
        ['GET', '/auth/account/credentials'],
      ]

      for (const [method, path] of routes) {
        const res = await handler(new Request(`http://localhost${path}`, { method }))
        expect(res.status).toBe(401)
      }
    })

    it('validates required fields', async () => {
      const auth = makeAuth()
      const handler = auth.createHandler()
      const res = await handler(new Request('http://localhost/auth/passkey/register/verify', {
        method: 'POST',
        body: JSON.stringify({}),
        headers: { 'Content-Type': 'application/json' },
      }))
      expect(res.status).toBe(400)
      expect((await res.json()).error).toContain('Missing or invalid field')
    })

    it('authenticated account routes work with valid session', async () => {
      const auth = makeAuth()
      const handler = auth.createHandler()

      // Set up a user with a session
      await storage.createUser({ id: 'u1', email: 'a@b.com', createdAt: new Date() })
      await storage.createSession({
        id: 's1', token: 'valid-token', userId: 'u1',
        authMethod: 'passkey',
        expiresAt: new Date(Date.now() + 10000), createdAt: new Date(),
      })

      // GET /account
      const res = await handler(new Request('http://localhost/auth/account', {
        headers: { Authorization: 'Bearer valid-token' },
      }))
      expect(res.status).toBe(200)
      const body = await res.json()
      expect(body.user.id).toBe('u1')
    })

    it('lists sessions for authenticated user', async () => {
      const auth = makeAuth()
      const handler = auth.createHandler()

      await storage.createUser({ id: 'u1', createdAt: new Date() })
      await storage.createSession({
        id: 's1', token: 'tok1', userId: 'u1',
        authMethod: 'passkey',
        expiresAt: new Date(Date.now() + 10000), createdAt: new Date(),
      })
      await storage.createSession({
        id: 's2', token: 'tok2', userId: 'u1',
        authMethod: 'magic-link',
        expiresAt: new Date(Date.now() + 10000), createdAt: new Date(),
      })

      const res = await handler(new Request('http://localhost/auth/account/sessions', {
        headers: { Authorization: 'Bearer tok1' },
      }))
      expect(res.status).toBe(200)
      const body = await res.json()
      expect(body.sessions).toHaveLength(2)
    })

    it('deletes account via handler', async () => {
      const auth = makeAuth()
      const handler = auth.createHandler()

      await storage.createUser({ id: 'u1', createdAt: new Date() })
      await storage.createSession({
        id: 's1', token: 'tok1', userId: 'u1',
        authMethod: 'passkey',
        expiresAt: new Date(Date.now() + 10000), createdAt: new Date(),
      })

      const res = await handler(new Request('http://localhost/auth/account', {
        method: 'DELETE',
        headers: { Authorization: 'Bearer tok1' },
      }))
      expect(res.status).toBe(200)
      expect(await auth.getUser('u1')).toBeNull()
    })
  })
})
