import { generateId as defaultGenerateId, generateToken, hashToken, timingSafeEqual } from '../crypto.js'
import type { QRSession, QRSessionStatus, StorageAdapter } from '../types.js'

export interface QRSessionManager {
  create(): Promise<{ sessionId: string; statusToken: string; confirmationCode?: string }>
  getStatus(sessionId: string, statusToken: string): Promise<QRSessionStatus>
  markScanned(sessionId: string): Promise<void>
  confirm(sessionId: string, confirmationCode: string): Promise<void>
  beginChallenge(sessionId: string): Promise<void>
  complete(sessionId: string, userId: string, sessionToken: string): Promise<void>
  cancel(sessionId: string, statusToken: string): Promise<void>
}

export function createQRSessionManager(
  storage: StorageAdapter,
  opts: { ttl: number; generateId?: () => string; confirmation?: { enabled?: boolean; codeLength?: number } },
): QRSessionManager {
  const generateId = opts.generateId ?? defaultGenerateId
  const confirmationEnabled = opts.confirmation?.enabled === true
  const confirmationLength = Math.max(4, Math.min(8, opts.confirmation?.codeLength ?? 6))

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
    const statusTokenHash = await hashToken(statusToken)
    if (!statusToken || !(await timingSafeEqual(session.statusTokenHash, statusTokenHash))) {
      throw new Error('Invalid QR session token')
    }
    return session
  }

  return {
    async create() {
      const statusToken = generateToken(24)
      const confirmationCode = confirmationEnabled ? generateConfirmationCode(confirmationLength) : undefined
      const session: QRSession = {
        id: generateId(),
        state: 'created',
        statusTokenHash: await hashToken(statusToken),
        confirmationCodeHash: confirmationCode ? await hashToken(confirmationCode) : undefined,
        expiresAt: new Date(Date.now() + opts.ttl),
        createdAt: new Date(),
      }
      await storage.createQRSession(session)
      return { sessionId: session.id, statusToken, confirmationCode }
    },

    async getStatus(sessionId, statusToken) {
      const session = await requireStatusToken(sessionId, statusToken)

      const status: QRSessionStatus = { state: session.state }
      if (session.confirmationCodeHash) {
        status.confirmationRequired = true
        status.confirmed = !!session.confirmedAt
      }
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

    async confirm(sessionId, confirmationCode) {
      const session = await getLiveSession(sessionId)
      if (!session.confirmationCodeHash) return
      if (session.confirmedAt) return
      if (session.state !== 'scanned' && session.state !== 'challenged') {
        throw new Error(`QR session is ${session.state}, cannot confirm`)
      }
      const confirmationCodeHash = await hashToken(confirmationCode)
      if (!(await timingSafeEqual(session.confirmationCodeHash, confirmationCodeHash))) {
        throw new Error('Invalid QR confirmation code')
      }
      await storage.updateQRSession(sessionId, { confirmedAt: new Date() })
    },

    async beginChallenge(sessionId) {
      const session = await getLiveSession(sessionId)
      if (session.state === 'challenged') return
      if (session.state !== 'scanned') {
        throw new Error(`QR session is ${session.state}, cannot begin challenge`)
      }
      if (session.confirmationCodeHash && !session.confirmedAt) {
        throw new Error('QR session requires confirmation before challenge')
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
      if (session.confirmationCodeHash && !session.confirmedAt) {
        throw new Error('QR session requires confirmation before completion')
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

function generateConfirmationCode(length: number): string {
  const digits = '0123456789'
  let code = ''
  for (let i = 0; i < length; i++) {
    code += digits[Math.floor(Math.random() * digits.length)]
  }
  return code
}
