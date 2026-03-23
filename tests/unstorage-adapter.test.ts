import { describe, it, expect, beforeEach } from 'vitest'
import { createStorage } from 'unstorage'
import { unstorageAdapter } from '../src/adapters/unstorage.js'
import type { StorageAdapter, User, Credential } from '../src/types.js'

describe('unstorageAdapter', () => {
  let adapter: StorageAdapter

  beforeEach(() => {
    const storage = createStorage() // in-memory by default
    adapter = unstorageAdapter(storage)
  })

  // ── Users ──

  describe('users', () => {
    const user: User = { id: 'u1', email: 'test@example.com', createdAt: new Date() }

    it('creates and retrieves a user by id', async () => {
      await adapter.createUser(user)
      const found = await adapter.getUserById('u1')
      expect(found?.id).toBe('u1')
      expect(found?.email).toBe('test@example.com')
      expect(found?.createdAt).toBeInstanceOf(Date)
    })

    it('retrieves a user by email', async () => {
      await adapter.createUser(user)
      const found = await adapter.getUserByEmail('test@example.com')
      expect(found?.id).toBe('u1')
    })

    it('returns null for missing user', async () => {
      expect(await adapter.getUserById('nope')).toBeNull()
      expect(await adapter.getUserByEmail('nope@example.com')).toBeNull()
    })

    it('updates a user email', async () => {
      await adapter.createUser({ id: 'u2', createdAt: new Date() })
      const updated = await adapter.updateUser('u2', { email: 'new@example.com' })
      expect(updated.email).toBe('new@example.com')

      // Lookup by new email works
      const found = await adapter.getUserByEmail('new@example.com')
      expect(found?.id).toBe('u2')
    })

    it('updates email index when changing email', async () => {
      await adapter.createUser({ id: 'u3', email: 'old@example.com', createdAt: new Date() })
      await adapter.updateUser('u3', { email: 'new@example.com' })

      expect(await adapter.getUserByEmail('old@example.com')).toBeNull()
      expect((await adapter.getUserByEmail('new@example.com'))?.id).toBe('u3')
    })

    it('deletes a user and cleans up email index', async () => {
      await adapter.createUser({ id: 'u4', email: 'del@example.com', createdAt: new Date() })
      await adapter.deleteUser('u4')
      expect(await adapter.getUserById('u4')).toBeNull()
      expect(await adapter.getUserByEmail('del@example.com')).toBeNull()
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
      await adapter.createCredential(cred)
      const found = await adapter.getCredentialById('cred1')
      expect(found?.id).toBe('cred1')
      expect(found?.publicKey).toBeInstanceOf(Uint8Array)
      expect(found?.publicKey[0]).toBe(1)
    })

    it('retrieves credentials by user id', async () => {
      await adapter.createCredential(cred)
      await adapter.createCredential({ ...cred, id: 'cred2' })
      const found = await adapter.getCredentialsByUserId('u1')
      expect(found).toHaveLength(2)
    })

    it('updates counter', async () => {
      await adapter.createCredential(cred)
      await adapter.updateCredential('cred1', { counter: 42 })
      const found = await adapter.getCredentialById('cred1')
      expect(found?.counter).toBe(42)
    })

    it('updates label', async () => {
      await adapter.createCredential(cred)
      await adapter.updateCredential('cred1', { label: 'YubiKey' })
      const found = await adapter.getCredentialById('cred1')
      expect(found?.label).toBe('YubiKey')
    })

    it('deletes credential and updates index', async () => {
      await adapter.createCredential(cred)
      await adapter.createCredential({ ...cred, id: 'cred2' })
      await adapter.deleteCredential('cred1')

      expect(await adapter.getCredentialById('cred1')).toBeNull()
      const remaining = await adapter.getCredentialsByUserId('u1')
      expect(remaining).toHaveLength(1)
      expect(remaining[0].id).toBe('cred2')
    })
  })

  // ── Sessions ──

  describe('sessions', () => {
    it('creates and retrieves session by token', async () => {
      await adapter.createSession({
        id: 's1',
        token: 'tok1',
        userId: 'u1',
        authMethod: 'passkey',
        expiresAt: new Date(Date.now() + 10000),
        createdAt: new Date(),
      })
      const found = await adapter.getSessionByToken('tok1')
      expect(found?.id).toBe('s1')
      expect(found?.expiresAt).toBeInstanceOf(Date)
    })

    it('lists sessions by user id (excluding expired)', async () => {
      await adapter.createSession({
        id: 's-live', token: 'tok-live', userId: 'u1',
        authMethod: 'passkey',
        expiresAt: new Date(Date.now() + 10000), createdAt: new Date(),
      })
      await adapter.createSession({
        id: 's-dead', token: 'tok-dead', userId: 'u1',
        authMethod: 'magic-link',
        expiresAt: new Date(Date.now() - 1000), createdAt: new Date(),
      })
      const sessions = await adapter.getSessionsByUserId('u1')
      expect(sessions).toHaveLength(1)
      expect(sessions[0].id).toBe('s-live')
    })

    it('returns null for expired session', async () => {
      await adapter.createSession({
        id: 's2',
        token: 'tok2',
        userId: 'u1',
        authMethod: 'passkey',
        expiresAt: new Date(Date.now() - 1000),
        createdAt: new Date(),
      })
      expect(await adapter.getSessionByToken('tok2')).toBeNull()
    })

    it('deletes sessions by user id', async () => {
      await adapter.createSession({
        id: 's3',
        token: 'tok3',
        userId: 'u1',
        authMethod: 'passkey',
        expiresAt: new Date(Date.now() + 10000),
        createdAt: new Date(),
      })
      await adapter.createSession({
        id: 's4',
        token: 'tok4',
        userId: 'u1',
        authMethod: 'passkey',
        expiresAt: new Date(Date.now() + 10000),
        createdAt: new Date(),
      })
      await adapter.deleteSessionsByUserId('u1')
      expect(await adapter.getSessionByToken('tok3')).toBeNull()
      expect(await adapter.getSessionByToken('tok4')).toBeNull()
    })
  })

  // ── Challenges ──

  describe('challenges', () => {
    it('stores and retrieves a challenge', async () => {
      await adapter.storeChallenge('c1', 'challenge-value', 10000)
      expect(await adapter.getChallenge('c1')).toBe('challenge-value')
    })

    it('returns null for expired challenge', async () => {
      await adapter.storeChallenge('c2', 'val', 0)
      await new Promise((r) => setTimeout(r, 5))
      expect(await adapter.getChallenge('c2')).toBeNull()
    })

    it('deletes challenge', async () => {
      await adapter.storeChallenge('c3', 'val', 10000)
      await adapter.deleteChallenge('c3')
      expect(await adapter.getChallenge('c3')).toBeNull()
    })
  })

  // ── Magic Links ──

  describe('magic links', () => {
    it('stores and retrieves a magic link', async () => {
      await adapter.storeMagicLink('tok', 'a@b.com', 10000)
      const found = await adapter.getMagicLink('tok')
      expect(found?.email).toBe('a@b.com')
    })

    it('returns null for expired magic link', async () => {
      await adapter.storeMagicLink('tok2', 'a@b.com', 0)
      await new Promise((r) => setTimeout(r, 5))
      expect(await adapter.getMagicLink('tok2')).toBeNull()
    })

    it('deletes magic link', async () => {
      await adapter.storeMagicLink('tok3', 'a@b.com', 10000)
      await adapter.deleteMagicLink('tok3')
      expect(await adapter.getMagicLink('tok3')).toBeNull()
    })
  })

  // ── QR Sessions ──

  describe('QR sessions', () => {
    it('creates and retrieves QR session', async () => {
      await adapter.createQRSession({
        id: 'qr1',
        state: 'created',
        expiresAt: new Date(Date.now() + 10000),
        createdAt: new Date(),
      })
      const found = await adapter.getQRSession('qr1')
      expect(found?.state).toBe('created')
      expect(found?.expiresAt).toBeInstanceOf(Date)
    })

    it('marks expired QR session', async () => {
      await adapter.createQRSession({
        id: 'qr2',
        state: 'challenged',
        expiresAt: new Date(Date.now() - 1000),
        createdAt: new Date(),
      })
      const found = await adapter.getQRSession('qr2')
      expect(found?.state).toBe('expired')
    })

    it('updates QR session', async () => {
      await adapter.createQRSession({
        id: 'qr3',
        state: 'created',
        expiresAt: new Date(Date.now() + 10000),
        createdAt: new Date(),
      })
      await adapter.updateQRSession('qr3', { state: 'authenticated', userId: 'u1' })
      const found = await adapter.getQRSession('qr3')
      expect(found?.state).toBe('authenticated')
      expect(found?.userId).toBe('u1')
    })
  })

  // ── Custom base prefix ──

  describe('custom base prefix', () => {
    it('isolates data with different prefixes', async () => {
      const storage = createStorage()
      const adapter1 = unstorageAdapter(storage, { base: 'app1' })
      const adapter2 = unstorageAdapter(storage, { base: 'app2' })

      await adapter1.createUser({ id: 'u1', email: 'a@b.com', createdAt: new Date() })
      expect(await adapter2.getUserById('u1')).toBeNull()
      expect(await adapter1.getUserById('u1')).not.toBeNull()
    })
  })
})
