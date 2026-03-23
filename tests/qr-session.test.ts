import { describe, it, expect, beforeEach } from 'vitest'
import { memoryAdapter } from '../src/adapters/memory.js'
import { createQRSessionManager } from '../src/server/qr-session.js'
import type { StorageAdapter } from '../src/types.js'

describe('QRSessionManager', () => {
  let storage: StorageAdapter
  let qr: ReturnType<typeof createQRSessionManager>

  beforeEach(() => {
    storage = memoryAdapter()
    qr = createQRSessionManager(storage, { ttl: 5 * 60 * 1000 })
  })

  it('creates a QR session', async () => {
    const { sessionId, statusToken } = await qr.create()
    expect(sessionId).toBeTruthy()
    expect(statusToken).toBeTruthy()
    const status = await qr.getStatus(sessionId, statusToken)
    expect(status.state).toBe('created')
  })

  it('marks session as scanned', async () => {
    const { sessionId, statusToken } = await qr.create()
    await qr.markScanned(sessionId)
    const status = await qr.getStatus(sessionId, statusToken)
    expect(status.state).toBe('scanned')
  })

  it('completes a session', async () => {
    const { sessionId, statusToken } = await qr.create()
    await qr.markScanned(sessionId)
    await qr.beginChallenge(sessionId)
    await qr.complete(sessionId, 'user-1', 'session-token')
    const status = await qr.getStatus(sessionId, statusToken)
    expect(status.state).toBe('authenticated')
    expect(status.session?.token).toBe('session-token')
  })

  it('prevents completing an already completed session', async () => {
    const { sessionId } = await qr.create()
    await qr.markScanned(sessionId)
    await qr.beginChallenge(sessionId)
    await qr.complete(sessionId, 'user-1', 'session-token')
    await expect(qr.complete(sessionId, 'user-2', 'session-token-2')).rejects.toThrow('cannot complete')
  })

  it('allows duplicate scan calls while challenge has not completed', async () => {
    const { sessionId } = await qr.create()
    await qr.markScanned(sessionId)
    await expect(qr.markScanned(sessionId)).resolves.toBeUndefined()
  })

  it('prevents challenge before scan', async () => {
    const { sessionId } = await qr.create()
    await expect(qr.beginChallenge(sessionId)).rejects.toThrow('cannot begin challenge')
  })

  it('marks expired sessions', async () => {
    const expiredQr = createQRSessionManager(storage, { ttl: 0 })
    const { sessionId, statusToken } = await expiredQr.create()
    // Small delay to ensure expiry
    await new Promise((r) => setTimeout(r, 5))
    const status = await expiredQr.getStatus(sessionId, statusToken)
    expect(status.state).toBe('expired')
  })

  it('expires scanned sessions too', async () => {
    const expiredQr = createQRSessionManager(storage, { ttl: 0 })
    const { sessionId, statusToken } = await expiredQr.create()
    await expiredQr.markScanned(sessionId)
    await new Promise((r) => setTimeout(r, 5))
    const status = await expiredQr.getStatus(sessionId, statusToken)
    expect(status.state).toBe('expired')
  })

  it('cancels an active session', async () => {
    const { sessionId, statusToken } = await qr.create()
    await qr.cancel(sessionId, statusToken)
    const status = await qr.getStatus(sessionId, statusToken)
    expect(status.state).toBe('cancelled')
  })

  it('rejects status polling with the wrong token', async () => {
    const { sessionId } = await qr.create()
    await expect(qr.getStatus(sessionId, 'wrong-token')).rejects.toThrow('Invalid QR session token')
  })

  it('throws for unknown session', async () => {
    await expect(qr.getStatus('nonexistent', 'token')).rejects.toThrow('not found')
  })
})
