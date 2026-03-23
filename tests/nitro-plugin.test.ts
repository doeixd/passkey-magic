import { describe, it, expect, beforeEach, vi } from 'vitest'
import { createStorage } from 'unstorage'
import { passkeyMagic, useAuth } from '../src/nitro/index.js'
import { hashToken } from '../src/crypto.js'

function createMockNitroApp() {
  const hooks = new Map<string, Function[]>()
  return {
    hooks: {
      hook(event: string, handler: Function) {
        if (!hooks.has(event)) hooks.set(event, [])
        hooks.get(event)!.push(handler)
        return () => {
          const handlers = hooks.get(event)
          if (handlers) {
            const idx = handlers.indexOf(handler)
            if (idx !== -1) handlers.splice(idx, 1)
          }
        }
      },
    },
    // Helper to trigger hooks in tests
    _trigger: async (event: string, ...args: any[]) => {
      const handlers = hooks.get(event) ?? []
      for (const handler of handlers) {
        await handler(...args)
      }
    },
  }
}

describe('Nitro plugin', () => {
  it('sets up auth and makes it accessible via useAuth()', () => {
    const storage = createStorage()
    const nitroApp = createMockNitroApp()

    const plugin = passkeyMagic({
      rpName: 'Test App',
      rpID: 'localhost',
      origin: 'http://localhost:3000',
      storage,
    })

    plugin.setup(nitroApp as any)

    const auth = useAuth()
    expect(auth).toBeDefined()
    expect(auth.generateRegistrationOptions).toBeTypeOf('function')
    expect(auth.createQRSession).toBeTypeOf('function')
  })

  it('throws if useAuth() called before setup', async () => {
    // Clean up by triggering close on any previous plugin
    const storage = createStorage()
    const nitroApp = createMockNitroApp()
    const plugin = passkeyMagic({
      rpName: 'Test App',
      rpID: 'localhost',
      origin: 'http://localhost:3000',
      storage,
    })
    plugin.setup(nitroApp as any)
    await nitroApp._trigger('close')

    expect(() => useAuth()).toThrow('auth not initialized')
  })

  it('throws if no storage provided', () => {
    const nitroApp = createMockNitroApp()
    const plugin = passkeyMagic({
      rpName: 'Test App',
      rpID: 'localhost',
      origin: 'http://localhost:3000',
    })

    expect(() => plugin.setup(nitroApp as any)).toThrow('storage is required')
  })

  it('cleans up on close', async () => {
    const storage = createStorage()
    const nitroApp = createMockNitroApp()

    passkeyMagic({
      rpName: 'Test App',
      rpID: 'localhost',
      origin: 'http://localhost:3000',
      storage,
    }).setup(nitroApp as any)

    // Auth should work
    expect(useAuth()).toBeDefined()

    // Trigger close
    await nitroApp._trigger('close')

    // Auth should be cleaned up
    expect(() => useAuth()).toThrow('auth not initialized')
  })

  it('handles auth routes via request hook', async () => {
    const storage = createStorage()
    const nitroApp = createMockNitroApp()

    passkeyMagic({
      rpName: 'Test App',
      rpID: 'localhost',
      origin: 'http://localhost:3000',
      storage,
      pathPrefix: '/api/auth',
    }).setup(nitroApp as any)

    // Simulate a QR session creation through the request hook
    const auth = useAuth()
    const { sessionId, statusToken } = await auth.createQRSession()
    expect(sessionId).toBeTruthy()
    expect(statusToken).toBeTruthy()
  })

  it('uses unstorage for data persistence', async () => {
    const storage = createStorage()
    const nitroApp = createMockNitroApp()

    passkeyMagic({
      rpName: 'Test App',
      rpID: 'localhost',
      origin: 'http://localhost:3000',
      storage,
      storageBase: 'myauth',
    }).setup(nitroApp as any)

    const auth = useAuth()
    const { sessionId, statusToken } = await auth.createQRSession()

    // Verify the data is in unstorage under the correct prefix
    const qrData = await storage.getItem(`myauth:qr:${sessionId}`)
    expect(qrData).toBeDefined()
    expect((qrData as any).state).toBe('created')
    expect((qrData as any).statusTokenHash).toBe(await hashToken(statusToken))
  })

  it('supports magic link when email adapter is provided', () => {
    const storage = createStorage()
    const nitroApp = createMockNitroApp()
    const emailAdapter = { sendMagicLink: vi.fn(async () => {}) }

    passkeyMagic({
      rpName: 'Test App',
      rpID: 'localhost',
      origin: 'http://localhost:3000',
      storage,
      email: emailAdapter,
      magicLinkURL: 'http://localhost:3000/verify',
    }).setup(nitroApp as any)

    const auth = useAuth()
    expect((auth as any).sendMagicLink).toBeTypeOf('function')
  })

  it('does not have magic link methods without email adapter', () => {
    const storage = createStorage()
    const nitroApp = createMockNitroApp()

    passkeyMagic({
      rpName: 'Test App',
      rpID: 'localhost',
      origin: 'http://localhost:3000',
      storage,
    }).setup(nitroApp as any)

    const auth = useAuth()
    expect((auth as any).sendMagicLink).toBeUndefined()
  })

  it('accepts a raw StorageAdapter instead of unstorage', async () => {
    const nitroApp = createMockNitroApp()
    const { memoryAdapter } = await import('../src/adapters/memory.js')
    const adapter = memoryAdapter()

    passkeyMagic({
      rpName: 'Test App',
      rpID: 'localhost',
      origin: 'http://localhost:3000',
      storage: adapter as any,
    }).setup(nitroApp as any)

    const auth = useAuth()
    const { sessionId, statusToken } = await auth.createQRSession()
    expect(sessionId).toBeTruthy()
    expect(statusToken).toBeTruthy()
  })
})
