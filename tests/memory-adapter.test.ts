import { describe, it, expect, beforeEach } from 'vitest'
import { memoryAdapter } from '../src/adapters/memory.js'
import type { StorageAdapter, User, Credential } from '../src/types.js'

describe('memoryAdapter', () => {
  let storage: StorageAdapter

  beforeEach(() => {
    storage = memoryAdapter()
  })

  // ── Users ──

  describe('users', () => {
    const user: User = { id: 'u1', email: 'test@example.com', createdAt: new Date() }

    it('creates and retrieves a user by id', async () => {
      await storage.createUser(user)
      const found = await storage.getUserById('u1')
      expect(found).toEqual(user)
    })

    it('retrieves a user by email', async () => {
      await storage.createUser(user)
      const found = await storage.getUserByEmail('test@example.com')
      expect(found).toEqual(user)
    })

    it('returns null for missing user', async () => {
      expect(await storage.getUserById('nope')).toBeNull()
      expect(await storage.getUserByEmail('nope@example.com')).toBeNull()
    })

    it('updates a user', async () => {
      await storage.createUser({ id: 'u2', createdAt: new Date() })
      const updated = await storage.updateUser('u2', { email: 'new@example.com' })
      expect(updated.email).toBe('new@example.com')
      const fetched = await storage.getUserById('u2')
      expect(fetched?.email).toBe('new@example.com')
    })

    it('returns independent copies (no mutation)', async () => {
      const created = await storage.createUser(user)
      created.email = 'mutated@example.com'
      const fetched = await storage.getUserById('u1')
      expect(fetched?.email).toBe('test@example.com')
    })

    it('deletes a user', async () => {
      await storage.createUser(user)
      await storage.deleteUser('u1')
      expect(await storage.getUserById('u1')).toBeNull()
    })
  })

  // ── Credentials ──

  describe('credentials', () => {
    const cred: Credential = {
      id: 'cred1',
      userId: 'u1',
      publicKey: new Uint8Array([1, 2, 3]),
      counter: 0,
      deviceType: 'singleDevice',
      backedUp: false,
      createdAt: new Date(),
    }

    it('creates and retrieves credential by id', async () => {
      await storage.createCredential(cred)
      const found = await storage.getCredentialById('cred1')
      expect(found?.id).toBe('cred1')
      expect(found?.userId).toBe('u1')
    })

    it('retrieves credentials by user id', async () => {
      await storage.createCredential(cred)
      await storage.createCredential({ ...cred, id: 'cred2' })
      const found = await storage.getCredentialsByUserId('u1')
      expect(found).toHaveLength(2)
    })

    it('updates counter', async () => {
      await storage.createCredential(cred)
      await storage.updateCredential('cred1', { counter: 5 })
      const found = await storage.getCredentialById('cred1')
      expect(found?.counter).toBe(5)
    })

    it('updates label', async () => {
      await storage.createCredential(cred)
      await storage.updateCredential('cred1', { label: 'My iPhone' })
      const found = await storage.getCredentialById('cred1')
      expect(found?.label).toBe('My iPhone')
    })

    it('throws when updating nonexistent credential', async () => {
      await expect(
        storage.updateCredential('nope', { counter: 1 }),
      ).rejects.toThrow('Credential not found')
    })

    it('deletes credential', async () => {
      await storage.createCredential(cred)
      await storage.deleteCredential('cred1')
      expect(await storage.getCredentialById('cred1')).toBeNull()
    })
  })

  // ── Sessions ──

  describe('sessions', () => {
    it('creates and retrieves session by token', async () => {
      await storage.createSession({
        id: 's1',
        token: 'tok1',
        userId: 'u1',
        expiresAt: new Date(Date.now() + 10000),
        createdAt: new Date(),
      })
      const found = await storage.getSessionByToken('tok1')
      expect(found?.id).toBe('s1')
    })

    it('lists sessions by user id (excluding expired)', async () => {
      await storage.createSession({
        id: 's-active', token: 'tok-active', userId: 'u1',
        expiresAt: new Date(Date.now() + 10000), createdAt: new Date(),
      })
      await storage.createSession({
        id: 's-expired', token: 'tok-expired', userId: 'u1',
        expiresAt: new Date(Date.now() - 1000), createdAt: new Date(),
      })
      const sessions = await storage.getSessionsByUserId('u1')
      expect(sessions).toHaveLength(1)
      expect(sessions[0].id).toBe('s-active')
    })

    it('returns null for expired session', async () => {
      await storage.createSession({
        id: 's2',
        token: 'tok2',
        userId: 'u1',
        expiresAt: new Date(Date.now() - 1000),
        createdAt: new Date(),
      })
      expect(await storage.getSessionByToken('tok2')).toBeNull()
    })

    it('deletes sessions by user id', async () => {
      await storage.createSession({
        id: 's3',
        token: 'tok3',
        userId: 'u1',
        expiresAt: new Date(Date.now() + 10000),
        createdAt: new Date(),
      })
      await storage.createSession({
        id: 's4',
        token: 'tok4',
        userId: 'u1',
        expiresAt: new Date(Date.now() + 10000),
        createdAt: new Date(),
      })
      await storage.deleteSessionsByUserId('u1')
      expect(await storage.getSessionByToken('tok3')).toBeNull()
      expect(await storage.getSessionByToken('tok4')).toBeNull()
    })
  })

  // ── Challenges ──

  describe('challenges', () => {
    it('stores and retrieves a challenge', async () => {
      await storage.storeChallenge('c1', 'challenge-value', 10000)
      expect(await storage.getChallenge('c1')).toBe('challenge-value')
    })

    it('returns null for expired challenge', async () => {
      await storage.storeChallenge('c2', 'val', 0) // expires immediately
      // Small delay to ensure expiry
      await new Promise((r) => setTimeout(r, 5))
      expect(await storage.getChallenge('c2')).toBeNull()
    })

    it('deletes challenge', async () => {
      await storage.storeChallenge('c3', 'val', 10000)
      await storage.deleteChallenge('c3')
      expect(await storage.getChallenge('c3')).toBeNull()
    })
  })

  // ── Magic Links ──

  describe('magic links', () => {
    it('stores and retrieves a magic link', async () => {
      await storage.storeMagicLink('tok', 'a@b.com', 10000)
      const found = await storage.getMagicLink('tok')
      expect(found?.email).toBe('a@b.com')
    })

    it('returns null for expired magic link', async () => {
      await storage.storeMagicLink('tok2', 'a@b.com', 0)
      await new Promise((r) => setTimeout(r, 5))
      expect(await storage.getMagicLink('tok2')).toBeNull()
    })

    it('deletes magic link', async () => {
      await storage.storeMagicLink('tok3', 'a@b.com', 10000)
      await storage.deleteMagicLink('tok3')
      expect(await storage.getMagicLink('tok3')).toBeNull()
    })
  })

  // ── QR Sessions ──

  describe('QR sessions', () => {
    it('creates and retrieves QR session', async () => {
      await storage.createQRSession({
        id: 'qr1',
        state: 'pending',
        expiresAt: new Date(Date.now() + 10000),
        createdAt: new Date(),
      })
      const found = await storage.getQRSession('qr1')
      expect(found?.state).toBe('pending')
    })

    it('marks expired QR session', async () => {
      await storage.createQRSession({
        id: 'qr2',
        state: 'pending',
        expiresAt: new Date(Date.now() - 1000),
        createdAt: new Date(),
      })
      const found = await storage.getQRSession('qr2')
      expect(found?.state).toBe('expired')
    })

    it('updates QR session', async () => {
      await storage.createQRSession({
        id: 'qr3',
        state: 'pending',
        expiresAt: new Date(Date.now() + 10000),
        createdAt: new Date(),
      })
      await storage.updateQRSession('qr3', { state: 'authenticated', userId: 'u1' })
      const found = await storage.getQRSession('qr3')
      expect(found?.state).toBe('authenticated')
      expect(found?.userId).toBe('u1')
    })
  })
})
