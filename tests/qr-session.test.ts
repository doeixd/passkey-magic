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
    const { sessionId } = await qr.create()
    expect(sessionId).toBeTruthy()
    const status = await qr.getStatus(sessionId)
    expect(status.state).toBe('pending')
  })

  it('marks session as scanned', async () => {
    const { sessionId } = await qr.create()
    await qr.markScanned(sessionId)
    const status = await qr.getStatus(sessionId)
    expect(status.state).toBe('scanned')
  })

  it('completes a session', async () => {
    const { sessionId } = await qr.create()
    await qr.complete(sessionId, 'user-1')
    const status = await qr.getStatus(sessionId)
    expect(status.state).toBe('authenticated')
  })

  it('prevents completing an already completed session', async () => {
    const { sessionId } = await qr.create()
    await qr.complete(sessionId, 'user-1')
    await expect(qr.complete(sessionId, 'user-2')).rejects.toThrow('cannot complete')
  })

  it('prevents scanning a non-pending session', async () => {
    const { sessionId } = await qr.create()
    await qr.markScanned(sessionId)
    await expect(qr.markScanned(sessionId)).rejects.toThrow('expected pending')
  })

  it('marks expired sessions', async () => {
    const expiredQr = createQRSessionManager(storage, { ttl: 0 })
    const { sessionId } = await expiredQr.create()
    // Small delay to ensure expiry
    await new Promise((r) => setTimeout(r, 5))
    const status = await expiredQr.getStatus(sessionId)
    expect(status.state).toBe('expired')
  })

  it('throws for unknown session', async () => {
    await expect(qr.getStatus('nonexistent')).rejects.toThrow('not found')
  })
})
