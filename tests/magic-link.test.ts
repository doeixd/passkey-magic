import { describe, it, expect, beforeEach, vi } from 'vitest'
import { memoryAdapter } from '../src/adapters/memory.js'
import { createMagicLinkManager } from '../src/server/magic-link.js'
import type { EmailAdapter, StorageAdapter } from '../src/types.js'

describe('MagicLinkManager', () => {
  let storage: StorageAdapter
  let emailAdapter: EmailAdapter
  let sentEmails: { email: string; url: string; token: string }[]

  beforeEach(() => {
    storage = memoryAdapter()
    sentEmails = []
    emailAdapter = {
      sendMagicLink: vi.fn(async (email, url, token) => {
        sentEmails.push({ email, url, token })
      }),
    }
  })

  function createManager() {
    return createMagicLinkManager(storage, emailAdapter, {
      magicLinkURL: 'https://app.com/auth/verify',
      ttl: 15 * 60 * 1000,
    })
  }

  it('sends a magic link email', async () => {
    const manager = createManager()
    const result = await manager.send({ email: 'test@example.com' })
    expect(result.sent).toBe(true)
    expect(sentEmails).toHaveLength(1)
    expect(sentEmails[0].email).toBe('test@example.com')
    expect(sentEmails[0].url).toContain('https://app.com/auth/verify?token=')
  })

  it('verifies a magic link and creates a new user', async () => {
    const manager = createManager()
    await manager.send({ email: 'new@example.com' })
    const token = sentEmails[0].token

    const result = await manager.verify({ token })
    expect(result.isNewUser).toBe(true)
    expect(result.user.email).toBe('new@example.com')
    expect(result.user.id).toBeTruthy()
  })

  it('verifies a magic link and finds existing user', async () => {
    const manager = createManager()

    // Create existing user
    await storage.createUser({ id: 'existing', email: 'old@example.com', createdAt: new Date() })

    await manager.send({ email: 'old@example.com' })
    const token = sentEmails[0].token

    const result = await manager.verify({ token })
    expect(result.isNewUser).toBe(false)
    expect(result.user.id).toBe('existing')
  })

  it('rejects invalid token', async () => {
    const manager = createManager()
    await expect(manager.verify({ token: 'bad' })).rejects.toThrow('Magic link expired or invalid')
  })

  it('token is single-use', async () => {
    const manager = createManager()
    await manager.send({ email: 'test@example.com' })
    const token = sentEmails[0].token

    await manager.verify({ token })
    await expect(manager.verify({ token })).rejects.toThrow('Magic link expired or invalid')
  })
})
