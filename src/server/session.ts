import { generateId, generateToken } from '../crypto.js'
import type { Session, StorageAdapter } from '../types.js'

/** Internal session manager used by `createAuth()`. */
export interface SessionManager {
  create(userId: string, meta?: { userAgent?: string; ipAddress?: string }): Promise<Session>
  validate(token: string): Promise<Session | null>
  listByUser(userId: string): Promise<Session[]>
  revoke(id: string): Promise<void>
  revokeAll(userId: string): Promise<void>
}

export function createSessionManager(
  storage: StorageAdapter,
  opts: { ttl: number; generateId?: () => string },
): SessionManager {
  const id = opts.generateId ?? generateId

  return {
    async create(userId, meta) {
      const session: Session = {
        id: id(),
        token: generateToken(),
        userId,
        expiresAt: new Date(Date.now() + opts.ttl),
        createdAt: new Date(),
        userAgent: meta?.userAgent,
        ipAddress: meta?.ipAddress,
      }
      return storage.createSession(session)
    },

    async validate(token) {
      const session = await storage.getSessionByToken(token)
      if (!session) return null
      if (new Date() > session.expiresAt) {
        await storage.deleteSession(session.id)
        return null
      }
      return session
    },

    async listByUser(userId) {
      return storage.getSessionsByUserId(userId)
    },

    async revoke(id) {
      await storage.deleteSession(id)
    },

    async revokeAll(userId) {
      await storage.deleteSessionsByUserId(userId)
    },
  }
}
