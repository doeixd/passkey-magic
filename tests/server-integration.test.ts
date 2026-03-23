import { describe, it, expect, vi, beforeEach } from 'vitest'
import { createStorage } from 'unstorage'
import { createAuth } from '../src/server/index.js'
import { createUnstorageRateLimiter } from '../src/server/rate-limit.js'
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
      expect(auth.passkeys.register.start).toBeTypeOf('function')
      expect(auth.passkeys.register.finish).toBeTypeOf('function')
      expect(auth.passkeys.signIn.start).toBeTypeOf('function')
      expect(auth.passkeys.signIn.finish).toBeTypeOf('function')
    })

    it('has passkey management methods', () => {
      const auth = makeAuth()
      expect(auth.addPasskey).toBeTypeOf('function')
      expect(auth.verifyAddPasskey).toBeTypeOf('function')
      expect(auth.updateCredential).toBeTypeOf('function')
      expect(auth.removeCredential).toBeTypeOf('function')
      expect(auth.getUserCredentials).toBeTypeOf('function')
      expect(auth.passkeys.add.start).toBeTypeOf('function')
      expect(auth.passkeys.add.finish).toBeTypeOf('function')
      expect(auth.passkeys.list).toBeTypeOf('function')
      expect(auth.passkeys.update).toBeTypeOf('function')
      expect(auth.passkeys.remove).toBeTypeOf('function')
    })

    it('has QR methods', () => {
      const auth = makeAuth()
      expect(auth.createQRSession).toBeTypeOf('function')
      expect(auth.getQRSessionStatus).toBeTypeOf('function')
      expect(auth.markQRSessionScanned).toBeTypeOf('function')
      expect(auth.completeQRSession).toBeTypeOf('function')
      expect(auth.qr.create).toBeTypeOf('function')
      expect(auth.qr.getStatus).toBeTypeOf('function')
      expect(auth.qr.markScanned).toBeTypeOf('function')
      expect(auth.qr.complete).toBeTypeOf('function')
      expect(auth.qr.cancel).toBeTypeOf('function')
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
      expect(auth.accounts.get).toBeTypeOf('function')
      expect(auth.accounts.getByEmail).toBeTypeOf('function')
      expect(auth.accounts.isEmailAvailable).toBeTypeOf('function')
      expect(auth.accounts.canLinkEmail).toBeTypeOf('function')
      expect(auth.accounts.linkEmail).toBeTypeOf('function')
      expect(auth.accounts.unlinkEmail).toBeTypeOf('function')
      expect(auth.accounts.delete).toBeTypeOf('function')
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
      }) as any
      expect(auth.sendMagicLink).toBeTypeOf('function')
      expect(auth.verifyMagicLink).toBeTypeOf('function')
      expect(auth.magicLinks.send).toBeTypeOf('function')
      expect(auth.magicLinks.verify).toBeTypeOf('function')
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
      }) as any
      await expect(
        auth.sendMagicLink({ email: 'test@example.com' }),
      ).rejects.toThrow('Magic link blocked by hook')
    })

    it('blocks unauthenticated passkey registration for an existing user id', async () => {
      const auth = makeAuth()
      await storage.createUser({ id: 'victim', email: 'victim@example.com', createdAt: new Date() })

      await expect(
        auth.generateRegistrationOptions({ userId: 'victim' }),
      ).rejects.toThrow('existing user without authentication')
    })

    it('stores user-bound auth challenge metadata for scoped passkey sign-in', async () => {
      const auth = makeAuth()
      const { options } = await auth.generateAuthenticationOptions({ userId: 'u1' })
      const stored = await storage.getChallenge(`auth:${options.challenge}`)

      expect(stored).toContain('"userId":"u1"')
      expect(stored).toContain(options.challenge)
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

  describe('grouped API aliases', () => {
    it('delegates passkey register.start to generateRegistrationOptions', async () => {
      const auth = makeAuth()
      const result = await auth.passkeys.register.start({ email: 'grouped@example.com' })
      expect(result.userId).toBeTruthy()
      expect(result.options.challenge).toBeTruthy()
    })

    it('delegates qr aliases to base methods', async () => {
      const auth = makeAuth()
      const { sessionId, statusToken } = await auth.qr.create()
      expect((await auth.qr.getStatus({ sessionId, statusToken })).state).toBe('created')
      await auth.qr.markScanned(sessionId)
      expect((await auth.getQRSessionStatus({ sessionId, statusToken })).state).toBe('scanned')
      await auth.qr.cancel({ sessionId, statusToken })
      expect((await auth.qr.getStatus({ sessionId, statusToken })).state).toBe('cancelled')
    })

    it('delegates magic link aliases to base methods', async () => {
      const sentEmails: { token: string }[] = []
      const auth = makeAuth({
        email: {
          sendMagicLink: vi.fn(async (_email: string, _url: string, token: string) => {
            sentEmails.push({ token })
          }),
        } as EmailAdapter,
        magicLinkURL: 'http://localhost:3000/auth/verify',
      }) as any

      await auth.magicLinks.send({ email: 'grouped@example.com' })
      const result = await auth.magicLinks.verify({ token: sentEmails[0].token })
      expect(result.method).toBe('magic-link')
      expect(result.session.authMethod).toBe('magic-link')
    })

    it('delegates account aliases to base methods', async () => {
      const auth = makeAuth()
      await storage.createUser({ id: 'u-accounts', email: 'accounts@example.com', createdAt: new Date() })

      expect((await auth.accounts.get('u-accounts'))?.email).toBe('accounts@example.com')
      expect((await auth.accounts.getByEmail('accounts@example.com'))?.id).toBe('u-accounts')
      expect(await auth.accounts.isEmailAvailable('free@example.com')).toBe(true)
      expect(await auth.accounts.canLinkEmail({ userId: 'u-accounts', email: 'new@example.com' })).toEqual({ ok: true })
      expect(await auth.accounts.canLinkEmail({ userId: 'u-accounts', email: 'bad-email' })).toEqual({
        ok: false,
        reason: 'invalid_email',
      })
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
      }) as any

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
      }) as any
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

    it('rejects oversized token-like inputs', async () => {
      const auth = makeAuth({
        email: { sendMagicLink: vi.fn(async () => {}) } as EmailAdapter,
        magicLinkURL: 'http://localhost:3000/auth/verify',
      }) as any
      const handler = auth.createHandler()
      const oversized = 'x'.repeat(2048)

      const magicLinkRes = await handler(new Request('http://localhost/auth/magic-link/verify', {
        method: 'POST',
        body: JSON.stringify({ token: oversized }),
        headers: { 'Content-Type': 'application/json' },
      }))
      expect(magicLinkRes.status).toBe(400)

      const sessionRes = await handler(new Request('http://localhost/auth/session', {
        method: 'GET',
        headers: { Authorization: `Bearer ${oversized}` },
      }))
      expect(sessionRes.status).toBe(401)
    })

    it('rejects oversized labels and emails', async () => {
      const auth = makeAuth()
      const handler = auth.createHandler()
      await storage.createUser({ id: 'u1', createdAt: new Date() })
      await storage.createCredential({
        id: 'c1', userId: 'u1', publicKey: new Uint8Array([1]), counter: 0,
        deviceType: 'singleDevice', backedUp: false, createdAt: new Date(),
      })
      await storage.createSession({
        id: 's1', token: 'valid-token', userId: 'u1', authMethod: 'passkey',
        expiresAt: new Date(Date.now() + 10000), createdAt: new Date(),
      })

      const labelRes = await handler(new Request('http://localhost/auth/account/credentials/c1', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer valid-token' },
        body: JSON.stringify({ label: 'a'.repeat(201) }),
      }))
      expect(labelRes.status).toBe(400)

      const emailRes = await handler(new Request('http://localhost/auth/account/link-email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer valid-token' },
        body: JSON.stringify({ email: `${'a'.repeat(255)}@example.com` }),
      }))
      expect(emailRes.status).toBe(400)
    })

    it('rate limits magic link send when configured', async () => {
      const auth = makeAuth({
        email: { sendMagicLink: vi.fn(async () => {}) } as EmailAdapter,
        magicLinkURL: 'http://localhost:3000/auth/verify',
        rateLimit: {
          rules: {
            'magicLink.send': { limit: 1, windowMs: 60_000 },
          },
        },
      }) as any
      const handler = auth.createHandler()

      const first = await handler(new Request('http://localhost/auth/magic-link/send', {
        method: 'POST',
        body: JSON.stringify({ email: 'rate@example.com' }),
        headers: { 'Content-Type': 'application/json' },
      }))
      expect(first.status).toBe(200)

      const second = await handler(new Request('http://localhost/auth/magic-link/send', {
        method: 'POST',
        body: JSON.stringify({ email: 'rate@example.com' }),
        headers: { 'Content-Type': 'application/json' },
      }))
      expect(second.status).toBe(429)
    })

    it('allows disabling a rate-limited route explicitly', async () => {
      const auth = makeAuth({
        rateLimit: {
          rules: {
            'qr.create': null,
          },
        },
      })
      const handler = auth.createHandler()

      const first = await handler(new Request('http://localhost/auth/qr/create', { method: 'POST' }))
      const second = await handler(new Request('http://localhost/auth/qr/create', { method: 'POST' }))
      expect(first.status).toBe(200)
      expect(second.status).toBe(200)
    })

    it('supports a shared unstorage-backed rate limiter', async () => {
      const limiterStorage = createStorage()
      const limiter = createUnstorageRateLimiter(limiterStorage)
      const auth = makeAuth({
        email: { sendMagicLink: vi.fn(async () => {}) } as EmailAdapter,
        magicLinkURL: 'http://localhost:3000/auth/verify',
        rateLimit: {
          limiter,
          rules: {
            'magicLink.send': { limit: 1, windowMs: 60_000 },
          },
        },
      }) as any
      const handler = auth.createHandler()

      const first = await handler(new Request('http://localhost/auth/magic-link/send', {
        method: 'POST',
        body: JSON.stringify({ email: 'shared@example.com' }),
        headers: { 'Content-Type': 'application/json' },
      }))
      expect(first.status).toBe(200)

      const second = await handler(new Request('http://localhost/auth/magic-link/send', {
        method: 'POST',
        body: JSON.stringify({ email: 'shared@example.com' }),
        headers: { 'Content-Type': 'application/json' },
      }))
      expect(second.status).toBe(429)
    })

    it('handles QR session lifecycle', async () => {
      const auth = makeAuth()
      const handler = auth.createHandler()

      // Create
      const createRes = await handler(new Request('http://localhost/auth/qr/create', { method: 'POST' }))
      expect(createRes.status).toBe(200)
      const { sessionId, statusToken } = await createRes.json()

      // Poll
      const statusRes = await handler(new Request(`http://localhost/auth/qr/${sessionId}/status?token=${encodeURIComponent(statusToken)}`))
      expect(statusRes.status).toBe(200)
      expect((await statusRes.json()).state).toBe('created')

      // Scan
      const scanRes = await handler(new Request(`http://localhost/auth/qr/${sessionId}/scanned`, { method: 'POST' }))
      expect(scanRes.status).toBe(200)

      // Cancel
      const cancelRes = await handler(new Request(`http://localhost/auth/qr/${sessionId}/cancel`, {
        method: 'POST',
        body: JSON.stringify({ statusToken }),
        headers: { 'Content-Type': 'application/json' },
      }))
      expect(cancelRes.status).toBe(200)
    })

    it('rejects QR status polling without the desktop status token', async () => {
      const auth = makeAuth()
      const handler = auth.createHandler()
      const createRes = await handler(new Request('http://localhost/auth/qr/create', { method: 'POST' }))
      const { sessionId } = await createRes.json()

      const statusRes = await handler(new Request(`http://localhost/auth/qr/${sessionId}/status`))
      expect(statusRes.status).toBe(401)
    })

    it('rejects QR cancellation with the wrong desktop status token', async () => {
      const auth = makeAuth()
      const handler = auth.createHandler()
      const createRes = await handler(new Request('http://localhost/auth/qr/create', { method: 'POST' }))
      const { sessionId } = await createRes.json()

      const cancelRes = await handler(new Request(`http://localhost/auth/qr/${sessionId}/cancel`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ statusToken: 'wrong-token' }),
      }))
      expect(cancelRes.status).toBe(400)
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

    it('supports account identity helper routes', async () => {
      const auth = makeAuth()
      const handler = auth.createHandler()

      await storage.createUser({ id: 'u1', email: 'a@b.com', createdAt: new Date() })
      await storage.createSession({
        id: 's1', token: 'valid-token', userId: 'u1', authMethod: 'passkey',
        expiresAt: new Date(Date.now() + 10000), createdAt: new Date(),
      })

      const canLinkRes = await handler(new Request('http://localhost/auth/account/can-link-email', {
        method: 'POST',
        body: JSON.stringify({ email: 'free@example.com' }),
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'Bearer valid-token',
        },
      }))
      expect(canLinkRes.status).toBe(200)
      expect(await canLinkRes.json()).toEqual({ ok: true })
    })

    it('updates account and credential metadata via handler', async () => {
      const auth = makeAuth()
      const handler = auth.createHandler()

      await storage.createUser({ id: 'u1', email: 'a@b.com', createdAt: new Date() })
      await storage.createCredential({
        id: 'c1', userId: 'u1', publicKey: new Uint8Array([1]), counter: 0,
        deviceType: 'singleDevice', backedUp: false, createdAt: new Date(),
      })
      await storage.createSession({
        id: 's1', token: 'valid-token', userId: 'u1', authMethod: 'passkey',
        expiresAt: new Date(Date.now() + 10000), createdAt: new Date(),
      })

      const accountRes = await handler(new Request('http://localhost/auth/account/update', {
        method: 'POST',
        body: JSON.stringify({ metadata: { tier: 'pro' } }),
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'Bearer valid-token',
        },
      }))
      expect(accountRes.status).toBe(200)
      expect((await auth.getUser('u1'))?.metadata).toEqual({ tier: 'pro' })

      const credRes = await handler(new Request('http://localhost/auth/account/credentials/c1', {
        method: 'POST',
        body: JSON.stringify({ metadata: { nickname: 'Phone' } }),
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'Bearer valid-token',
        },
      }))
      expect(credRes.status).toBe(200)
      expect((await auth.getUserCredentials('u1'))[0].metadata).toEqual({ nickname: 'Phone' })
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

    it('supports client-compatible mutation aliases', async () => {
      const auth = makeAuth()
      const handler = auth.createHandler()

      await storage.createUser({ id: 'u1', email: 'a@b.com', createdAt: new Date() })
      await storage.createCredential({
        id: 'c1', userId: 'u1', publicKey: new Uint8Array([1]), counter: 0,
        deviceType: 'singleDevice', backedUp: false, createdAt: new Date(),
      })
      await storage.createCredential({
        id: 'c2', userId: 'u1', publicKey: new Uint8Array([2]), counter: 0,
        deviceType: 'singleDevice', backedUp: false, createdAt: new Date(),
      })
      await storage.createSession({
        id: 's1', token: 'tok1', userId: 'u1', authMethod: 'passkey',
        expiresAt: new Date(Date.now() + 10000), createdAt: new Date(),
      })
      await storage.createSession({
        id: 's2', token: 'tok2', userId: 'u1', authMethod: 'passkey',
        expiresAt: new Date(Date.now() + 10000), createdAt: new Date(),
      })

      const updateRes = await handler(new Request('http://localhost/auth/account/credentials/c1', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer tok1' },
        body: JSON.stringify({ label: 'Updated label' }),
      }))
      expect(updateRes.status).toBe(200)

      const deleteCredRes = await handler(new Request('http://localhost/auth/account/credentials/c2/delete', {
        method: 'POST',
        headers: { Authorization: 'Bearer tok1' },
      }))
      expect(deleteCredRes.status).toBe(200)

      const revokeSessionRes = await handler(new Request('http://localhost/auth/account/sessions/s2/delete', {
        method: 'POST',
        headers: { Authorization: 'Bearer tok1' },
      }))
      expect(revokeSessionRes.status).toBe(200)

      const revokeCurrentRes = await handler(new Request('http://localhost/auth/session/revoke', {
        method: 'POST',
        headers: { Authorization: 'Bearer tok1' },
      }))
      expect(revokeCurrentRes.status).toBe(200)
    })

    it('prevents cross-account credential and session mutations', async () => {
      const auth = makeAuth()
      const handler = auth.createHandler()

      await storage.createUser({ id: 'u1', createdAt: new Date() })
      await storage.createUser({ id: 'u2', email: 'b@b.com', createdAt: new Date() })
      await storage.createCredential({
        id: 'other-cred', userId: 'u2', publicKey: new Uint8Array([9]), counter: 0,
        deviceType: 'singleDevice', backedUp: false, createdAt: new Date(),
      })
      await storage.createSession({
        id: 'own-session', token: 'own-token', userId: 'u1', authMethod: 'passkey',
        expiresAt: new Date(Date.now() + 10000), createdAt: new Date(),
      })
      await storage.createSession({
        id: 'other-session', token: 'other-token', userId: 'u2', authMethod: 'passkey',
        expiresAt: new Date(Date.now() + 10000), createdAt: new Date(),
      })

      const credRes = await handler(new Request('http://localhost/auth/account/credentials/other-cred/delete', {
        method: 'POST',
        headers: { Authorization: 'Bearer own-token' },
      }))
      expect(credRes.status).toBe(404)

      const sessionRes = await handler(new Request('http://localhost/auth/account/sessions/other-session/delete', {
        method: 'POST',
        headers: { Authorization: 'Bearer own-token' },
      }))
      expect(sessionRes.status).toBe(404)
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
