import { generateId as defaultGenerateId } from '../crypto.js'
import type { QRSession, QRSessionStatus, StorageAdapter } from '../types.js'

export interface QRSessionManager {
  create(): Promise<{ sessionId: string }>
  getStatus(sessionId: string): Promise<QRSessionStatus>
  markScanned(sessionId: string): Promise<void>
  complete(sessionId: string, userId: string): Promise<void>
}

export function createQRSessionManager(
  storage: StorageAdapter,
  opts: { ttl: number; generateId?: () => string },
): QRSessionManager {
  const generateId = opts.generateId ?? defaultGenerateId

  return {
    async create() {
      const session: QRSession = {
        id: generateId(),
        state: 'pending',
        expiresAt: new Date(Date.now() + opts.ttl),
        createdAt: new Date(),
      }
      await storage.createQRSession(session)
      return { sessionId: session.id }
    },

    async getStatus(sessionId) {
      const session = await storage.getQRSession(sessionId)
      if (!session) {
        throw new Error('QR session not found')
      }

      if (new Date() > session.expiresAt && session.state === 'pending') {
        await storage.updateQRSession(sessionId, { state: 'expired' })
        return { state: 'expired' }
      }

      const status: QRSessionStatus = { state: session.state }
      if (session.state === 'authenticated' && session.sessionToken) {
        status.session = {
          token: session.sessionToken,
          expiresAt: session.expiresAt.toISOString(),
        }
      }
      return status
    },

    async markScanned(sessionId) {
      const session = await storage.getQRSession(sessionId)
      if (!session) throw new Error('QR session not found')
      if (session.state !== 'pending') throw new Error(`QR session is ${session.state}, expected pending`)
      await storage.updateQRSession(sessionId, { state: 'scanned' })
    },

    async complete(sessionId, userId) {
      const session = await storage.getQRSession(sessionId)
      if (!session) throw new Error('QR session not found')
      if (session.state !== 'pending' && session.state !== 'scanned') {
        throw new Error(`QR session is ${session.state}, cannot complete`)
      }
      await storage.updateQRSession(sessionId, {
        state: 'authenticated',
        userId,
      })
    },
  }
}
