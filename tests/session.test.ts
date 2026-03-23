import { describe, it, expect, beforeEach } from 'vitest'
import { memoryAdapter } from '../src/adapters/memory.js'
import { createSessionManager } from '../src/server/session.js'
import type { StorageAdapter } from '../src/types.js'

describe('SessionManager', () => {
  let storage: StorageAdapter
  let sessions: ReturnType<typeof createSessionManager>

  beforeEach(() => {
    storage = memoryAdapter()
    sessions = createSessionManager(storage, { ttl: 10000 })
  })

  it('creates a session with a token', async () => {
    const session = await sessions.create('user-1', 'passkey')
    expect(session.userId).toBe('user-1')
    expect(session.authMethod).toBe('passkey')
    expect(session.token).toBeTruthy()
    expect(session.id).toBeTruthy()
    expect(session.expiresAt.getTime()).toBeGreaterThan(Date.now())
  })

  it('validates a valid session', async () => {
    const created = await sessions.create('user-1', 'magic-link')
    const found = await sessions.validate(created.token)
    expect(found?.userId).toBe('user-1')
    expect(found?.authMethod).toBe('magic-link')
  })

  it('returns null for invalid token', async () => {
    expect(await sessions.validate('bad-token')).toBeNull()
  })

  it('revokes a session', async () => {
    const session = await sessions.create('user-1', 'passkey')
    await sessions.revoke(session.id)
    expect(await sessions.validate(session.token)).toBeNull()
  })

  it('revokes all sessions for a user', async () => {
    const s1 = await sessions.create('user-1', 'passkey')
    const s2 = await sessions.create('user-1', 'passkey')
    await sessions.revokeAll('user-1')
    expect(await sessions.validate(s1.token)).toBeNull()
    expect(await sessions.validate(s2.token)).toBeNull()
  })

  it('uses custom generateId when provided', async () => {
    let counter = 0
    const custom = createSessionManager(storage, {
      ttl: 10000,
      generateId: () => `custom-${++counter}`,
    })
    const session = await custom.create('user-1', 'passkey')
    expect(session.id).toBe('custom-1')
  })

  it('stores auth context when provided', async () => {
    const session = await sessions.create('user-1', 'qr', {
      authContext: { qrSessionId: 'qr-1' },
    })
    expect(session.authContext).toEqual({ qrSessionId: 'qr-1' })
  })
})
