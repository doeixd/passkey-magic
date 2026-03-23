import { generateId as defaultGenerateId, generateToken, timingSafeEqual } from '../crypto.js'
import type { QRSession, QRSessionStatus, StorageAdapter } from '../types.js'

export interface QRSessionManager {
  create(): Promise<{ sessionId: string; statusToken: string }>
  getStatus(sessionId: string, statusToken: string): Promise<QRSessionStatus>
  markScanned(sessionId: string): Promise<void>
  beginChallenge(sessionId: string): Promise<void>
  complete(sessionId: string, userId: string, sessionToken: string): Promise<void>
  cancel(sessionId: string, statusToken: string): Promise<void>
}

export function createQRSessionManager(
  storage: StorageAdapter,
  opts: { ttl: number; generateId?: () => string },
): QRSessionManager {
  const generateId = opts.generateId ?? defaultGenerateId

  function isTerminal(state: QRSession['state']): boolean {
    return state === 'authenticated' || state === 'expired' || state === 'cancelled'
  }

  async function getLiveSession(sessionId: string): Promise<QRSession> {
    const session = await storage.getQRSession(sessionId)
    if (!session) {
      throw new Error('QR session not found')
    }

    if (new Date() > session.expiresAt && !isTerminal(session.state)) {
      await storage.updateQRSession(sessionId, { state: 'expired' })
      return { ...session, state: 'expired' }
    }

    return session
  }

  async function requireStatusToken(sessionId: string, statusToken: string): Promise<QRSession> {
    const session = await getLiveSession(sessionId)
    if (!statusToken || !(await timingSafeEqual(session.statusToken, statusToken))) {
      throw new Error('Invalid QR session token')
    }
    return session
  }

  return {
    async create() {
      const session: QRSession = {
        id: generateId(),
        state: 'created',
        statusToken: generateToken(24),
        expiresAt: new Date(Date.now() + opts.ttl),
        createdAt: new Date(),
      }
      await storage.createQRSession(session)
      return { sessionId: session.id, statusToken: session.statusToken }
    },

    async getStatus(sessionId, statusToken) {
      const session = await requireStatusToken(sessionId, statusToken)

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
      const session = await getLiveSession(sessionId)
      if (session.state === 'scanned' || session.state === 'challenged') return
      if (session.state !== 'created') {
        throw new Error(`QR session is ${session.state}, expected created`)
      }
      await storage.updateQRSession(sessionId, { state: 'scanned', scannedAt: new Date() })
    },

    async beginChallenge(sessionId) {
      const session = await getLiveSession(sessionId)
      if (session.state === 'challenged') return
      if (session.state !== 'scanned') {
        throw new Error(`QR session is ${session.state}, cannot begin challenge`)
      }
      await storage.updateQRSession(sessionId, {
        state: 'challenged',
        challengedAt: new Date(),
      })
    },

    async complete(sessionId, userId, sessionToken) {
      const session = await getLiveSession(sessionId)
      if (session.state !== 'scanned' && session.state !== 'challenged') {
        throw new Error(`QR session is ${session.state}, cannot complete`)
      }
      await storage.updateQRSession(sessionId, {
        state: 'authenticated',
        userId,
        sessionToken,
        authenticatedAt: new Date(),
      })
    },

    async cancel(sessionId, statusToken) {
      const session = await requireStatusToken(sessionId, statusToken)
      if (session.state === 'cancelled') return
      if (isTerminal(session.state)) {
        throw new Error(`QR session is ${session.state}, cannot cancel`)
      }
      await storage.updateQRSession(sessionId, {
        state: 'cancelled',
        cancelledAt: new Date(),
      })
    },
  }
}
